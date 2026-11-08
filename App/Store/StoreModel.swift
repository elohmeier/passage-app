import AgeCrypto
import Foundation
import KeyStore
import Observation
import PassStore

/// The open password store: a folder picked in the Files app (git comes in M4).
@MainActor @Observable
final class StoreModel {
    private(set) var store: LocalStore?
    private(set) var snapshot = StoreSnapshot.empty
    private(set) var isLoading = false
    var errorMessage: String?

    private var access: FolderAccess?
    private var watcher: FolderWatcher?
    private var refreshTask: Task<Void, Never>?
    private let defaults: UserDefaults
    private static let bookmarkKey = "storeBookmark"

    var name: String { store?.root.lastPathComponent ?? "" }

    init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    /// Reopens the folder from the last session, if any.
    func restore() {
        guard store == nil, let bookmark = defaults.data(forKey: Self.bookmarkKey) else { return }
        do {
            let (access, refreshed) = try FolderAccess.resolve(bookmark: bookmark)
            if let refreshed { defaults.set(refreshed, forKey: Self.bookmarkKey) }
            attach(access)
        } catch {
            errorMessage = StoreError.accessDenied.localizedDescription
            defaults.removeObject(forKey: Self.bookmarkKey)
        }
    }

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

    func close() {
        watcher?.stop()
        access?.close()
        refreshTask?.cancel()
        watcher = nil
        access = nil
        store = nil
        snapshot = .empty
        defaults.removeObject(forKey: Self.bookmarkKey)
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
