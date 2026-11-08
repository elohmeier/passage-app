import Foundation
import GitHubKit
import GitSync
import Observation
import UIKit

/// The "Connect GitHub" setup: device flow sign-in, repository choice, deploy key, SSH clone.
/// The access token only lives in this object and is discarded when setup ends.
@MainActor @Observable
final class GitHubConnectModel {
    struct Candidate: Identifiable, Hashable {
        let repository: GitHubAPI.Repository
        /// Has an `.age-recipients` at the top level.
        let looksLikeStore: Bool
        var id: Int { repository.id }
    }

    enum Step: Equatable {
        case start
        case waitingForApproval(DeviceFlow.Code)
        case loading
        case needsInstallation
        case pickRepository([Candidate])
        case connecting(String)
        case failed(String)
    }

    private(set) var step = Step.start
    private var token: String?
    private var pollTask: Task<Void, Never>?
    let clientID: String
    let appSlug: String

    init(clientID: String, appSlug: String) {
        self.clientID = clientID
        self.appSlug = appSlug
    }

    #if DEBUG
        /// Screenshot hook: `-PassageGitHubStep code|picker|install`.
        func applyDebugStep() {
            let repo = { (id: Int, name: String, isPrivate: Bool) in
                GitHubAPI.Repository(
                    id: id, name: name, fullName: "alice/\(name)", private: isPrivate, sshURL: "git@github.com:alice/\(name).git",
                    defaultBranch: "main", pushedAt: .now)
            }
            switch UserDefaults.standard.string(forKey: "PassageGitHubStep") {
            case "code":
                step = .waitingForApproval(.init(
                    deviceCode: "x", userCode: "WDJB-MJHT", verificationURI: URL(string: "https://github.com/login/device")!,
                    expiresIn: 900, interval: 5))
            case "picker":
                step = .pickRepository([
                    Candidate(repository: repo(1, "password-store", true), looksLikeStore: true),
                    Candidate(repository: repo(2, "dotfiles", true), looksLikeStore: false),
                    Candidate(repository: repo(3, "blog", false), looksLikeStore: false),
                ])
            case "install": step = .needsInstallation
            default: break
            }
        }
    #endif

    var installURL: URL { URL(string: "https://github.com/apps/\(appSlug)/installations/new")! }

    /// Requests a device code, copies it, and polls for approval in the background.
    func start() async {
        let flow = DeviceFlow(clientID: clientID)
        do {
            let code = try await flow.requestCode()
            UIPasteboard.general.string = code.userCode
            step = .waitingForApproval(code)
            pollTask = Task {
                do {
                    token = try await flow.waitForToken(code)
                    await loadRepositories()
                } catch is CancellationError {
                } catch {
                    step = .failed(error.localizedDescription)
                }
            }
        } catch {
            step = .failed(error.localizedDescription)
        }
    }

    func loadRepositories() async {
        guard let token else { return }
        step = .loading
        let api = GitHubAPI(token: token)
        do {
            var repositories: [GitHubAPI.Repository] = []
            for installation in try await api.installations() {
                repositories += try await api.repositories(installation: installation.id)
            }
            guard !repositories.isEmpty else {
                step = .needsInstallation
                return
            }
            // Probe for .age-recipients concurrently; a failed probe just means "unknown".
            let probed = await withTaskGroup(of: Candidate.self) { group in
                for repo in repositories {
                    group.addTask {
                        Candidate(repository: repo, looksLikeStore: (try? await api.fileExists(".age-recipients", in: repo)) ?? false)
                    }
                }
                var all: [Candidate] = []
                for await candidate in group { all.append(candidate) }
                return all
            }
            step = .pickRepository(probed.sorted {
                if $0.looksLikeStore != $1.looksLikeStore { return $0.looksLikeStore }
                return ($0.repository.pushedAt ?? .distantPast) > ($1.repository.pushedAt ?? .distantPast)
            })
        } catch {
            step = .failed(error.localizedDescription)
        }
    }

    /// Adds a fresh per-store SSH key as a deploy key and clones over SSH.
    func connect(_ repository: GitHubAPI.Repository, store: StoreModel) async -> Bool {
        guard let token else { return false }
        let api = GitHubAPI(token: token)
        var keyName: String?
        var deployKey: GitHubAPI.DeployKey?
        do {
            step = .connecting(String(localized: "Creating a key in the Secure Enclave…"))
            let (key, name) = try store.newStoreSSHKey()
            keyName = name
            step = .connecting(String(localized: "Adding it as a deploy key…"))
            deployKey = try await api.addDeployKey(
                to: repository, title: "Passage on \(UIDevice.current.name)", key: try key.publicKeyLine(comment: "passage-ios"))

            step = .connecting(String(localized: "Cloning \(repository.fullName)…"))
            let link = GitStoreConfig.GitHubLink(fullName: repository.fullName, deployKeyID: deployKey!.id)
            do {
                try await store.clone(
                    remote: repository.sshURL, branch: repository.defaultBranch, username: "", password: "", sshKeyName: name,
                    gitHub: link)
            } catch let error as GitError where error.kind == .authentication {
                // A just-added deploy key can take a moment to become usable.
                try await Task.sleep(for: .seconds(3))
                try await store.clone(
                    remote: repository.sshURL, branch: repository.defaultBranch, username: "", password: "", sshKeyName: name,
                    gitHub: link)
            }
            finish()
            return true
        } catch {
            // Don't leave a dangling deploy key on GitHub or an orphaned key on the device.
            if let deployKey { try? await api.deleteDeployKey(deployKey.id, from: repository.fullName) }
            if let keyName { store.deleteSSHKey(named: keyName) }
            step = .failed(error.localizedDescription)
            return false
        }
    }

    /// Forgets the token. Called when setup completes or is cancelled.
    func finish() {
        pollTask?.cancel()
        token = nil
    }
}
