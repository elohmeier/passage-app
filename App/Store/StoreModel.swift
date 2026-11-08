import AgeCrypto
import Foundation
import GitSync
import KeyStore
import Observation
import PassStore

/// Where the open store comes from.
struct GitStoreConfig: Codable, Equatable {
    /// Directory name under `StoreModel.gitStoresRoot`.
    var directory: String
    var remote: String
    var branch: String?
    var username: String

    /// `git@host:path` or `ssh://…`.
    var usesSSH: Bool { Self.isSSH(remote) }

    static func isSSH(_ remote: String) -> Bool {
        remote.hasPrefix("ssh://") || remote.hasPrefix("git+ssh://") || remote.hasPrefix("ssh+git://")
            || (!remote.contains("://") && remote.contains(":") && !remote.hasPrefix("/"))
    }

    /// For github.com remotes, `owner/repo`.
    static func gitHubRepository(_ remote: String) -> String? {
        let path: Substring
        if let r = remote.range(of: "github.com:") {
            path = remote[r.upperBound...]
        } else if let r = remote.range(of: "github.com/") {
            path = remote[r.upperBound...]
        } else {
            return nil
        }
        let trimmed = path.hasSuffix(".git") ? path.dropLast(4) : path
        let parts = trimmed.split(separator: "/")
        return parts.count == 2 ? parts.joined(separator: "/") : nil
    }
}

/// The open password store: a folder picked in the Files app, or a git clone.
@MainActor @Observable
final class StoreModel {
    private(set) var store: LocalStore?
    private(set) var snapshot = StoreSnapshot.empty
    private(set) var isLoading = false
    var errorMessage: String?

    // Git
    private(set) var git: GitRepo?
    private(set) var gitConfig: GitStoreConfig?
    private(set) var lastCommit: GitRepo.Commit?
    private(set) var isSyncing = false
    private(set) var cloneProgress: GitProgress?

    private var access: FolderAccess?
    private var watcher: FolderWatcher?
    private var refreshTask: Task<Void, Never>?
    private let defaults: UserDefaults
    private let secrets: any SecretStore
    private static let bookmarkKey = "storeBookmark"
    private static let gitConfigKey = "gitStore"
    private static let gitPasswordKey = "git.password"
    private static let sshKeyKey = "ssh.key"
    private static let knownHostsKey = "knownHosts"

    /// Trusted SSH host keys, beyond the pinned ones.
    private(set) var knownHosts: KnownHosts

    var name: String {
        if let gitConfig { return Self.displayName(forRemote: gitConfig.remote) }
        return store?.root.lastPathComponent ?? ""
    }

    init(defaults: UserDefaults, secrets: any SecretStore) {
        self.defaults = defaults
        self.secrets = secrets
        knownHosts = defaults.data(forKey: Self.knownHostsKey).flatMap { try? JSONDecoder().decode(KnownHosts.self, from: $0) }
            ?? KnownHosts()
    }

    // MARK: SSH

    /// This device's SSH key, created on first use: in the Secure Enclave where available.
    func deviceSSHKey() throws -> SSHKey {
        if let data = try secrets.get(Self.sshKeyKey, context: nil), let key = try? JSONDecoder().decode(SSHKey.self, from: data) {
            return key
        }
        let key = (try? SSHKey.generateSecureEnclave()) ?? .generateEd25519()
        try secrets.set(try JSONEncoder().encode(key), for: Self.sshKeyKey, accessControl: nil)
        return key
    }

    func trust(_ key: HostKey) {
        knownHosts.trust(key)
        saveKnownHosts()
    }

    func forget(_ key: HostKey) {
        knownHosts.remove(key)
        saveKnownHosts()
    }

    private func saveKnownHosts() {
        defaults.set(try? JSONEncoder().encode(knownHosts), forKey: Self.knownHostsKey)
    }

    static var gitStoresRoot: URL {
        (FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppConfig.appGroup) ?? .applicationSupportDirectory)
            .appending(path: "Stores", directoryHint: .isDirectory)
    }

    /// Reopens the store from the last session, if any.
    func restore() {
        guard store == nil else { return }
        if let data = defaults.data(forKey: Self.gitConfigKey), let config = try? JSONDecoder().decode(GitStoreConfig.self, from: data) {
            do {
                try attachGit(config)
            } catch {
                errorMessage = error.localizedDescription
            }
            return
        }
        guard let bookmark = defaults.data(forKey: Self.bookmarkKey) else { return }
        do {
            let (access, refreshed) = try FolderAccess.resolve(bookmark: bookmark)
            if let refreshed { defaults.set(refreshed, forKey: Self.bookmarkKey) }
            attach(access)
        } catch {
            errorMessage = StoreError.accessDenied.localizedDescription
            defaults.removeObject(forKey: Self.bookmarkKey)
        }
    }

    // MARK: Files folder

    func open(pickedURL url: URL) {
        close()
        do {
            let (access, bookmark) = try FolderAccess.open(pickedURL: url)
            defaults.set(bookmark, forKey: Self.bookmarkKey)
            attach(access)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Creates the demo store, encrypted to this device's key (creating one if needed), and
    /// opens it.
    func openDemoStore(using model: AppModel, protection: KeyStore.KeyProtection? = nil) {
        guard let device = model.deviceIdentity ?? model.createDeviceIdentity(name: "This Device", protection: protection) else { return }
        do {
            let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppConfig.appGroup)
                ?? URL.applicationSupportDirectory
            let root = base.appending(path: "Demo Store", directoryHint: .isDirectory)
            try DemoStore.create(at: root, recipients: [RecipientParser.parse(device.recommendedRecipient(alongside: []))])
            open(pickedURL: root)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: Git

    /// Clones `remote` into the app's container and opens it. Throws so the clone sheet can
    /// show the error inline.
    func clone(remote: String, branch: String?, username: String, password: String) async throws {
        close()
        let directory = UUID().uuidString
        let target = Self.gitStoresRoot.appending(path: directory, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: Self.gitStoresRoot, withIntermediateDirectories: true)
        let credentials: GitCredentials = if GitStoreConfig.isSSH(remote) {
            .ssh(username: username.isEmpty ? nil : username, key: try deviceSSHKey())
        } else if password.isEmpty {
            .none
        } else {
            .userPassword(username: username, password: password)
        }

        cloneProgress = GitProgress(receivedObjects: 0, totalObjects: 0, receivedBytes: 0)
        defer { cloneProgress = nil }
        _ = try await GitRepo.clone(
            remote: remote, into: target, branch: branch, credentials: credentials, knownHosts: knownHosts
        ) { [weak self] progress in
            Task { @MainActor in self?.cloneProgress = progress }
        }

        let config = GitStoreConfig(directory: directory, remote: remote, branch: branch, username: username)
        if !password.isEmpty && !config.usesSSH {
            try secrets.set(Data(password.utf8), for: Self.gitPasswordKey, accessControl: nil)
        }
        defaults.set(try JSONEncoder().encode(config), forKey: Self.gitConfigKey)
        try attachGit(config)
    }

    /// Pulls (git) and rescans.
    func sync() async {
        guard let git, let gitConfig else {
            await refresh()
            return
        }
        isSyncing = true
        defer { isSyncing = false }
        do {
            _ = try await git.pull(credentials: storedCredentials(for: gitConfig), knownHosts: knownHosts)
            lastCommit = try? await git.headCommit()
        } catch {
            errorMessage = error.localizedDescription
        }
        await refresh()
    }

    private func storedCredentials(for config: GitStoreConfig) -> GitCredentials {
        if config.usesSSH, let key = try? deviceSSHKey() {
            return .ssh(username: config.username.isEmpty ? nil : config.username, key: key)
        }
        guard let data = try? secrets.get(Self.gitPasswordKey, context: nil) else { return .none }
        return .userPassword(username: config.username, password: String(decoding: data, as: UTF8.self))
    }

    private func attachGit(_ config: GitStoreConfig) throws {
        let root = Self.gitStoresRoot.appending(path: config.directory, directoryHint: .isDirectory)
        let repo = try GitRepo(opening: root)
        git = repo
        gitConfig = config
        store = LocalStore(root: root)
        Task {
            lastCommit = try? await repo.headCommit()
            await refresh()
        }
    }

    /// e.g. `github.com/alice/pass` → `pass`.
    static func displayName(forRemote remote: String) -> String {
        let last = remote.split(separator: "/").last.map(String.init) ?? remote
        return last.hasSuffix(".git") ? String(last.dropLast(4)) : last
    }

    // MARK: Common

    /// Forgets the store. A git clone lives inside the app and is deleted, together with its
    /// credentials; a Files folder is left untouched.
    func close() {
        watcher?.stop()
        access?.close()
        refreshTask?.cancel()
        if let gitConfig {
            try? FileManager.default.removeItem(at: Self.gitStoresRoot.appending(path: gitConfig.directory))
            try? secrets.delete(Self.gitPasswordKey)
        }
        watcher = nil
        access = nil
        store = nil
        git = nil
        gitConfig = nil
        lastCommit = nil
        snapshot = .empty
        defaults.removeObject(forKey: Self.bookmarkKey)
        defaults.removeObject(forKey: Self.gitConfigKey)
    }

    func refresh() async {
        guard let store else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            snapshot = try await store.snapshot()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func read(_ entry: EntryPath) async throws -> Data {
        guard let store else { throw StoreError.accessDenied }
        return try await store.read(entry)
    }

    private func attach(_ access: FolderAccess) {
        self.access = access
        store = LocalStore(root: access.url)
        watcher = FolderWatcher(url: access.url) { [weak self] in
            Task { @MainActor in self?.scheduleRefresh() }
        }
        Task { await refresh() }
    }

    /// Coalesces bursts of change notifications (a sync touching many files) into one rescan.
    private func scheduleRefresh() {
        refreshTask?.cancel()
        refreshTask = Task {
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            await refresh()
        }
    }
}
