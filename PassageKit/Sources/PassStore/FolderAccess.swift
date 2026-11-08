import Foundation

/// Long-lived access to a folder the user picked in the Files app.
///
/// The bookmark is stored in the App Group, so the app can reopen the folder on launch.
/// Access stays open until `close()`.
public final class FolderAccess: Sendable {
    public let url: URL
    private let scoped: Bool

    /// Opens a URL just returned by the document picker and returns its bookmark for storage.
    public static func open(pickedURL url: URL) throws -> (FolderAccess, bookmark: Data) {
        let scoped = url.startAccessingSecurityScopedResource()
        do {
            let bookmark = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
            return (FolderAccess(url: url, scoped: scoped), bookmark)
        } catch {
            if scoped { url.stopAccessingSecurityScopedResource() }
            throw error
        }
    }

    /// Reopens a stored bookmark. Returns a refreshed bookmark if the stored one was stale.
    public static func resolve(bookmark: Data) throws -> (FolderAccess, refreshedBookmark: Data?) {
        var stale = false
        let url = try URL(resolvingBookmarkData: bookmark, options: [], relativeTo: nil, bookmarkDataIsStale: &stale)
        let scoped = url.startAccessingSecurityScopedResource()
        guard scoped || FileManager.default.isReadableFile(atPath: url.path) else { throw StoreError.accessDenied }
        let refreshed = stale ? try? url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil) : nil
        return (FolderAccess(url: url, scoped: scoped), refreshed)
    }

    private init(url: URL, scoped: Bool) {
        self.url = url
        self.scoped = scoped
    }

    public func close() {
        if scoped { url.stopAccessingSecurityScopedResource() }
    }
}

/// Calls `onChange` when anything inside a folder changes, including changes made by other
/// apps or iCloud sync.
public final class FolderWatcher: NSObject, NSFilePresenter, @unchecked Sendable {
    public let presentedItemURL: URL?
    public let presentedItemOperationQueue: OperationQueue
    private let onChange: @Sendable () -> Void

    public init(url: URL, onChange: @escaping @Sendable () -> Void) {
        presentedItemURL = url
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        presentedItemOperationQueue = queue
        self.onChange = onChange
        super.init()
        NSFileCoordinator.addFilePresenter(self)
    }

    public func stop() {
        NSFileCoordinator.removeFilePresenter(self)
    }

    public func presentedItemDidChange() { onChange() }
    public func presentedSubitemDidChange(at url: URL) { onChange() }
    public func presentedSubitem(at oldURL: URL, didMoveTo newURL: URL) { onChange() }
    public func accommodatePresentedSubitemDeletion(at url: URL) async throws { onChange() }
}
