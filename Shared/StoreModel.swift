import AgeCrypto
import Foundation
import GitSync
import Network
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

    struct GitHubLink: Codable, Equatable, Identifiable {
        var id: Int { deployKeyID }
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
enum StoreModelError: LocalizedError {
    case recipientsNeedReview

    var errorDescription: String? {
        switch self {
        case .recipientsNeedReview: "The store's recipients changed. Review the change in Passage before saving new entries."
        }
    }
}

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
    private static let approvedRecipientsKey = "approvedRecipients"

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
        startMonitoringNetwork()
    }

    // MARK: SSH

    /// This device's SSH key, created on first use: in the Secure Enclave where available.
    func deviceSSHKey() throws -> SSHKey {
        if let data = try secrets.get(Self.sshKeyKey, context: nil), let key = try? JSONDecoder().decode(SSHKey.self, from: data) {
            return key
        }
        let key = (try? SSHKey.generateSecureEnclave()) ?? .generateEd25519()
        try secrets.setAvailableAfterFirstUnlock(try JSONEncoder().encode(key), for: Self.sshKeyKey)
        return key
    }

    /// Creates an SSH key for one store and returns it with its secret store name.
    func newStoreSSHKey() throws -> (key: SSHKey, name: String) {
        let key = (try? SSHKey.generateSecureEnclave()) ?? .generateEd25519()
        let name = "ssh.key.\(UUID().uuidString)"
        try secrets.setAvailableAfterFirstUnlock(try JSONEncoder().encode(key), for: name)
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

    /// Git clones are readable after the first unlock so background refresh can sync while
    /// the phone is locked. They only hold age-encrypted entries, file names and git metadata;
    /// the identities that decrypt them stay protected by Face ID. New files inherit the
    /// directory's class; existing ones are migrated here.
    static func relaxProtection(of url: URL) {
        let fm = FileManager.default
        let attributes: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        try? fm.setAttributes(attributes, ofItemAtPath: url.path)
        guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: nil) else { return }
        for case let item as URL in enumerator {
            try? fm.setAttributes(attributes, ofItemAtPath: item.path)
        }
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
            let entries = try DemoStore.create(at: root, recipients: [RecipientParser.parse(device.recommendedRecipient(alongside: []))])
            open(pickedURL: root)
            // The contents are known, so AutoFill works without running Prepare AutoFill.
            Task {
                await refresh()
                for entry in entries { await AutoFillStore.learn(entry.path, from: Entry(entry.content)) }
            }
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
        Self.relaxProtection(of: Self.gitStoresRoot)
        let credentials: GitCredentials = if GitStoreConfig.isSSH(remote) {
            .ssh(username: username.isEmpty ? nil : username, key: try sshKey(named: sshKeyName))
        } else if password.isEmpty {
            .none
        } else {
            .userPassword(username: username, password: password)
        }

        cloneProgress = GitProgress(receivedObjects: 0, totalObjects: 0, receivedBytes: 0)
        defer { cloneProgress = nil }
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        Self.relaxProtection(of: target)
        _ = try await GitRepo.clone(
            remote: remote, into: target, branch: branch, credentials: credentials, knownHosts: knownHosts
        ) { [weak self] progress in
            Task { @MainActor in self?.cloneProgress = progress }
        }

        let config = GitStoreConfig(
            directory: directory, remote: remote, branch: branch, username: username, sshKeyName: sshKeyName, gitHub: gitHub)
        if !password.isEmpty && !config.usesSSH {
            try secrets.setAvailableAfterFirstUnlock(Data(password.utf8), for: Self.gitPasswordKey)
        }
        defaults.set(try JSONEncoder().encode(config), forKey: Self.gitConfigKey)
        try attachGit(config)
    }

    // MARK: Readability

    /// How much of the store this device can decrypt, judged from stanza tags (no keys used).
    struct Readability: Equatable {
        /// Every .age-recipients lists this device.
        var isRecipient: Bool
        var unreadable: Set<EntryPath>
        var total: Int
        var readable: Int { total - unreadable.count }
    }

    private(set) var readability: Readability?

    /// Set by the app; used to judge readability and to add the device as a recipient.
    var identities: [StoredIdentity] = [] {
        didSet { if identities != oldValue { Task { await updateReadability() } } }
    }

    private var deviceIdentity: StoredIdentity? {
        identities.first { $0.kind == .secureEnclave || $0.kind == .simulator }
    }

    func updateReadability() async {
        guard let store, let device = deviceIdentity,
            device.recipients.contains(where: { (try? TagRecipient($0)) != nil })
        else {
            readability = nil
            return
        }
        let forms = Set(device.recipients)
        var isRecipient = true
        for folder in store.recipientsFiles() {
            let entry = EntryPath(folder.isEmpty ? "_" : folder + "/_")
            let encoded = (try? await store.recipients(for: entry).map(\.encoded)) ?? []
            if forms.isDisjoint(with: encoded) { isRecipient = false }
        }
        // Stanza types our imported identities might open; those entries count as readable.
        let importedTypes: Set<String> = Set(identities.filter { $0.kind == .imported }.flatMap { identity in
            identity.recipients.map { $0.hasPrefix("age1pq1") ? "mlkem768x25519" : "X25519" }
        })
        // The device key and any YubiKeys; tags are checked with public keys only.
        let tags = identities.filter { $0.kind != .imported }.compactMap { $0.recipients.lazy.compactMap { try? TagRecipient($0) }.first }
        let entries = snapshot.entries
        let headers = await store.headers(of: entries)
        let unreadable = Set(entries.filter { entry in
            guard let header = headers[entry] else { return false }
            return !tags.contains { $0.canDecrypt(header) } && !header.stanzas.contains { importedTypes.contains($0.type) }
        })
        readability = Readability(isRecipient: isRecipient, unreadable: unreadable, total: entries.count)
    }

    /// Adds this device's recipient to every .age-recipients that lacks it, then commits and syncs.
    func addDeviceAsRecipient() async throws {
        guard let store, let device = deviceIdentity else { return }
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        let name = UIDevice.current.name
        try await withWriteLock {
            let changed = try await store.addRecipient(
                present: Set(device.recipients), comment: "\(name) (Passage, \(f.string(from: .now)))"
            ) { device.recommendedRecipient(alongside: $0) }
            guard !changed.isEmpty else { return }
            await approveRecipients()
            await commitLocked("Add \(name) (Passage) as recipient.")
        }
    }

    /// True for a store without recipients or entries, e.g. a new GitHub repository: the app
    /// offers to set it up.
    private(set) var needsSetup = false

    /// Writes `.age-recipients` (this device and the recovery key) and a README, then commits
    /// and pushes. Returns true if the commit reached the remote.
    @discardableResult
    func setUpNewStore(device: StoredIdentity, recovery: RecoveryKit) async throws -> Bool {
        guard let store else { throw StoreError.accessDenied }
        let recoveryRecipient = try RecipientParser.parse(recovery.recipient)
        let files = NewStore.files(
            deviceRecipient: device.recommendedRecipient(alongside: [recoveryRecipient]), deviceName: UIDevice.current.name,
            recovery: recovery)
        return try await withWriteLock {
            try await store.setUp(files: files)
            await approveRecipients()
            return await commitLocked("Set up password store with Passage.")
        }
    }

    // MARK: Recipient changes

    /// `.age-recipients` changes since the user last approved them (pulled, or written by
    /// another device into a shared folder). New entries aren't encrypted until reviewed, so a
    /// recipient slipped into the remote doesn't silently receive new secrets.
    private(set) var recipientChanges: [RecipientSet.Change] = []
    /// The last sync stopped because both sides changed a `.age-recipients`.
    private(set) var recipientsConflict = false

    private func reviewRecipients() async {
        guard let store, let current = try? await store.recipientSet() else { return }
        guard let data = defaults.data(forKey: Self.approvedRecipientsKey),
            let approved = try? JSONDecoder().decode(RecipientSet.self, from: data)
        else {
            // First look at this store: what it has now is what the user chose to open.
            defaults.set(try? JSONEncoder().encode(current.set), forKey: Self.approvedRecipientsKey)
            recipientChanges = []
            return
        }
        recipientChanges = current.set.changes(since: approved, labels: current.labels)
    }

    /// Accepts the current recipients, e.g. after reviewing `recipientChanges`.
    func approveRecipients() async {
        guard let store, let current = try? await store.recipientSet() else { return }
        defaults.set(try? JSONEncoder().encode(current.set), forKey: Self.approvedRecipientsKey)
        recipientChanges = []
    }

    private func requireApprovedRecipients() async throws {
        await reviewRecipients()
        if !recipientChanges.isEmpty { throw StoreModelError.recipientsNeedReview }
    }

    /// Resolves `recipientsConflict` by keeping the remote's `.age-recipients` (ours is saved
    /// as a conflict copy). The resulting change still goes through recipient review.
    func syncKeepingRemoteRecipients() async {
        do {
            try await withWriteLock { await syncLocked(.user, acceptRemoteRecipients: true) }
        } catch {
            syncProblem = error.localizedDescription
        }
    }

    /// Set after a sync that had to keep both sides of conflicting edits.
    var conflictCopies: [String] = []

    enum SyncTrigger {
        /// App came to the foreground or the network came back: never interrupts with alerts.
        case automatic
        /// Pull to refresh, Sync Now, or saving a change.
        case user
    }

    /// Why the last sync failed, shown inline at the top of the store. Nil when fine.
    private(set) var syncProblem: String?
    private(set) var lastSynced: Date?
    private var pendingAutomaticSync = false
    private var isOnline = true
    private let pathMonitor = NWPathMonitor()

    /// Lets the app keep running briefly in the background so a sync isn't cut off when the
    /// device locks. Set by the app (extensions can't use UIApplication).
    static var beginBackgroundTask: (@MainActor () -> (@MainActor () -> Void))?

    /// Pulls and pushes (git), then rescans. Local commits stay if the network fails and go
    /// out with the next sync.
    func sync(_ trigger: SyncTrigger = .user) async {
        guard git != nil else {
            await refresh()
            return
        }
        if trigger == .automatic && (!isOnline || isSyncing) {
            if !isOnline { pendingAutomaticSync = true }
            return
        }
        do {
            try await withWriteLock { await syncLocked(trigger) }
        } catch {
            syncProblem = error.localizedDescription
        }
    }

    /// The sync itself; callers hold the write lock.
    private func syncLocked(_ trigger: SyncTrigger, acceptRemoteRecipients: Bool = false) async {
        guard let git, let gitConfig else { return }
        isSyncing = true
        let endBackgroundTask = Self.beginBackgroundTask?()
        defer {
            isSyncing = false
            endBackgroundTask?()
        }
        let credentials = storedCredentials(for: gitConfig)
        for attempt in 0..<2 {
            do {
                let result = try await git.sync(
                    credentials: credentials, knownHosts: knownHosts, author: Self.author, acceptRemoteRecipients: acceptRemoteRecipients)
                recipientsConflict = false
                if !result.conflictCopies.isEmpty { conflictCopies = result.conflictCopies }
                lastCommit = try? await git.headCommit()
                lastSynced = .now
                syncProblem = nil
                break
            } catch where error.isTransient && attempt == 0 {
                // Typical right after waking up: the network isn't quite back yet.
                try? await Task.sleep(for: .seconds(2))
                continue
            } catch {
                syncProblem = error.localizedDescription
                recipientsConflict = error.kind == .recipientsConflict
                // Automatic syncs report quietly; things the user asked for get an alert,
                // except plain connectivity problems, which the inline status covers.
                if trigger == .user, !error.isTransient {
                    errorMessage = error.localizedDescription
                }
                break
            }
        }
        await refresh()
    }

    private func startMonitoringNetwork() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let online = path.status == .satisfied
            Task { @MainActor in
                guard let self else { return }
                self.isOnline = online
                if online, self.pendingAutomaticSync {
                    self.pendingAutomaticSync = false
                    await self.sync(.automatic)
                }
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "StoreModel.network"))
    }

    // MARK: Writing

    static var author: GitRepo.Signature {
        GitRepo.Signature(name: "Passage on \(UIDevice.current.name)", email: "passage@\(UIDevice.current.model.lowercased()).invalid")
    }

    /// Encrypts and writes an entry, then commits and syncs (git). Returns true if the change
    /// reached the remote (always true for Files folders, which have no remote step).
    @discardableResult
    func save(_ entry: EntryPath, text: String, isNew: Bool, message: String? = nil) async throws -> Bool {
        guard let store else { throw StoreError.accessDenied }
        try await requireApprovedRecipients()
        return try await withWriteLock {
            try await store.save(entry, plaintext: Data(text.utf8))
            return await commitLocked(
                message ?? (isNew ? "Add given password for \(entry.path) to store." : "Edit password for \(entry.path) using Passage."))
        }
    }

    /// Writes many new entries in one commit (e.g. an import). Returns true if it reached the remote.
    @discardableResult
    func importEntries(_ entries: [(path: EntryPath, text: String)], message: String) async throws -> Bool {
        guard let store else { throw StoreError.accessDenied }
        try await requireApprovedRecipients()
        return try await withWriteLock {
            for entry in entries {
                try await store.save(entry.path, plaintext: Data(entry.text.utf8))
            }
            return await commitLocked(message)
        }
    }

    /// Saves edited content under a new name and removes the old one, as one commit.
    func rename(_ from: EntryPath, to: EntryPath, text: String) async throws {
        guard let store else { throw StoreError.accessDenied }
        try await requireApprovedRecipients()
        try await withWriteLock {
            try await store.save(to, plaintext: Data(text.utf8))
            try await store.delete(from)
            await commitLocked("Rename \(from.path) to \(to.path).")
        }
    }

    func delete(_ entry: EntryPath) async throws {
        guard let store else { throw StoreError.accessDenied }
        try await withWriteLock {
            try await store.delete(entry)
            await commitLocked("Remove \(entry.path) from store.")
        }
    }

    func move(_ from: EntryPath, to: EntryPath, decrypt: @escaping @Sendable (Data) async throws -> Data) async throws {
        guard let store else { throw StoreError.accessDenied }
        try await requireApprovedRecipients()
        try await withWriteLock {
            try await store.move(from, to: to, decrypt: decrypt)
            await commitLocked("Rename \(from.path) to \(to.path).")
        }
    }

    /// Serializes git work between the app and its extensions (AutoFill saves passkeys).
    private var gitLock: ProcessLock?

    private func withWriteLock<T>(_ body: () async throws -> T) async throws -> T {
        guard let gitLock else { return try await body() }
        return try await gitLock.withLock(body)
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

    /// Commits everything and syncs; callers hold the write lock. Returns true if the commit
    /// reached the remote.
    @discardableResult
    private func commitLocked(_ message: String) async -> Bool {
        guard let git else {
            await refresh()
            return true
        }
        do {
            try await git.commitAll(message: message, author: Self.author)
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
        await syncLocked(.user)
        return syncProblem == nil
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
        gitLock = ProcessLock(path: root.appending(path: ".git/passage.lock").path)
        migrateForBackgroundRefresh(config, root: root)
        store = LocalStore(root: root)
        Task {
            lastCommit = try? await repo.headCommit()
            await refresh()
        }
    }

    /// Stores set up before background refresh: relax the clone's file protection and move the
    /// sync credentials to after-first-unlock availability. Runs once per store.
    private func migrateForBackgroundRefresh(_ config: GitStoreConfig, root: URL) {
        let flag = "migratedBackgroundRefresh.\(config.directory)"
        guard !defaults.bool(forKey: flag) else { return }
        Self.relaxProtection(of: root)
        for key in [config.sshKeyName ?? Self.sshKeyKey, Self.gitPasswordKey] {
            if let data = try? secrets.get(key, context: nil) { try? secrets.setAvailableAfterFirstUnlock(data, for: key) }
        }
        defaults.set(true, forKey: flag)
    }

    /// e.g. `github.com/alice/pass` → `pass`.
    static func displayName(forRemote remote: String) -> String {
        let last = remote.split(separator: "/").last.map(String.init) ?? remote
        return last.hasSuffix(".git") ? String(last.dropLast(4)) : last
    }

    // MARK: Common

    /// Forgets the store. A git clone lives inside the app and is deleted, together with its
    /// credentials; a Files folder is left untouched.
    /// Changes that closing would lose: unpushed commits plus uncommitted files. Zero for
    /// Files folders, where closing deletes nothing.
    func unpushedChangeCount() async -> Int {
        guard let git, let work = try? await git.unpushedWork() else { return 0 }
        return work.commits + work.uncommitted
    }

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
        gitLock = nil
        lastCommit = nil
        syncProblem = nil
        lastSynced = nil
        snapshot = .empty
        needsSetup = false
        recipientChanges = []
        recipientsConflict = false
        defaults.removeObject(forKey: Self.approvedRecipientsKey)
        if updatesAutoFill { Task { await AutoFillStore.clear() } }
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
        needsSetup = snapshot.entries.isEmpty && NewStore.isEmpty(at: store.root)
        await reviewRecipients()
        if updatesAutoFill { await AutoFillStore.update(entries: snapshot.entries) }
        await updateReadability()
    }

    /// The app keeps the AutoFill index current; the extension only reads it.
    var updatesAutoFill = true

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
