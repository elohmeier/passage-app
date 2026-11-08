import AgeCrypto
import Foundation
import GitSync
import KeyStore
import Observation
import PassStore
import UIKit

/// Where the open store comes from.
struct GitStoreConfig: Codable, Equatable {
    /// Directory name under `StoreModel.gitStoresRoot`.
    var directory: String
    var remote: String
    var branch: String?
    var username: String
    /// Secret store key of this store's own SSH key (GitHub deploy keys must be unique per
    /// repository). Nil means the device's shared SSH key.
    var sshKeyName: String?
    /// Set for stores connected through "Connect GitHub".
    var gitHub: GitHubLink?

    struct GitHubLink: Codable, Equatable {
        var fullName: String
        var deployKeyID: Int
    }

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

    /// Creates an SSH key for one store and returns it with its secret store name.
    func newStoreSSHKey() throws -> (key: SSHKey, name: String) {
        let key = (try? SSHKey.generateSecureEnclave()) ?? .generateEd25519()
        let name = "ssh.key.\(UUID().uuidString)"
        try secrets.set(try JSONEncoder().encode(key), for: name, accessControl: nil)
        return (key, name)
    }

    func deleteSSHKey(named name: String) {
        try? secrets.delete(name)
    }

    private func sshKey(named name: String?) throws -> SSHKey {
        guard let name else { return try deviceSSHKey() }
        guard let data = try secrets.get(name, context: nil) else { throw StoreError.notFound("SSH key") }
        return try JSONDecoder().decode(SSHKey.self, from: data)
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
    func clone(
        remote: String, branch: String?, username: String, password: String, sshKeyName: String? = nil,
        gitHub: GitStoreConfig.GitHubLink? = nil
    ) async throws {
        close(keepingSSHKey: sshKeyName)
        let directory = UUID().uuidString
        let target = Self.gitStoresRoot.appending(path: directory, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: Self.gitStoresRoot, withIntermediateDirectories: true)
        let credentials: GitCredentials = if GitStoreConfig.isSSH(remote) {
            .ssh(username: username.isEmpty ? nil : username, key: try sshKey(named: sshKeyName))
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

        let config = GitStoreConfig(
            directory: directory, remote: remote, branch: branch, username: username, sshKeyName: sshKeyName, gitHub: gitHub)
        if !password.isEmpty && !config.usesSSH {
            try secrets.set(Data(password.utf8), for: Self.gitPasswordKey, accessControl: nil)
        }
        defaults.set(try JSONEncoder().encode(config), forKey: Self.gitConfigKey)
        try attachGit(config)
    }

    /// Set after a sync that had to keep both sides of conflicting edits.
    var conflictCopies: [String] = []

    /// Pulls and pushes (git), then rescans. Local commits stay if the network fails and go
    /// out with the next sync.
    func sync() async {
        guard let git, let gitConfig else {
            await refresh()
            return
        }
        isSyncing = true
        defer { isSyncing = false }
        do {
            let result = try await git.sync(credentials: storedCredentials(for: gitConfig), knownHosts: knownHosts, author: Self.author)
            if !result.conflictCopies.isEmpty { conflictCopies = result.conflictCopies }
            lastCommit = try? await git.headCommit()
        } catch {
            errorMessage = error.localizedDescription
        }
        await refresh()
    }

    // MARK: Writing

    static var author: GitRepo.Signature {
        GitRepo.Signature(name: "Passage on \(UIDevice.current.name)", email: "passage@\(UIDevice.current.model.lowercased()).invalid")
    }

    /// Encrypts and writes an entry, then commits and syncs (git).
    func save(_ entry: EntryPath, text: String, isNew: Bool) async throws {
        guard let store else { throw StoreError.accessDenied }
        try await store.save(entry, plaintext: Data(text.utf8))
        await commit(isNew ? "Add given password for \(entry.path) to store." : "Edit password for \(entry.path) using Passage.")
    }

    /// Saves edited content under a new name and removes the old one, as one commit.
    func rename(_ from: EntryPath, to: EntryPath, text: String) async throws {
        guard let store else { throw StoreError.accessDenied }
        try await store.save(to, plaintext: Data(text.utf8))
        try await store.delete(from)
        await commit("Rename \(from.path) to \(to.path).")
    }

    func delete(_ entry: EntryPath) async throws {
        guard let store else { throw StoreError.accessDenied }
        try await store.delete(entry)
        await commit("Remove \(entry.path) from store.")
    }

    func move(_ from: EntryPath, to: EntryPath, decrypt: @escaping @Sendable (Data) async throws -> Data) async throws {
        guard let store else { throw StoreError.accessDenied }
        try await store.move(from, to: to, decrypt: decrypt)
        await commit("Rename \(from.path) to \(to.path).")
    }

    /// The recipients a new or edited entry at `entry` will be encrypted to.
    func recipients(for entry: EntryPath) async -> Result<[String], any Error> {
        guard let store else { return .failure(StoreError.accessDenied) }
        do {
            return .success(try await store.recipients(for: entry).map(\.encoded))
        } catch {
            return .failure(error)
        }
    }

    private func commit(_ message: String) async {
        if let git {
            do {
                try await git.commitAll(message: message, author: Self.author)
            } catch {
                errorMessage = error.localizedDescription
            }
            await sync()
        } else {
            await refresh()
        }
    }

    private func storedCredentials(for config: GitStoreConfig) -> GitCredentials {
        if config.usesSSH, let key = try? sshKey(named: config.sshKeyName) {
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
    func close(keepingSSHKey keep: String? = nil) {
        watcher?.stop()
        access?.close()
        refreshTask?.cancel()
        if let gitConfig {
            try? FileManager.default.removeItem(at: Self.gitStoresRoot.appending(path: gitConfig.directory))
            try? secrets.delete(Self.gitPasswordKey)
            if let name = gitConfig.sshKeyName, name != keep { try? secrets.delete(name) }
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
