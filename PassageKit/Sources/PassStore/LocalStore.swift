import AgeCrypto
import Foundation

public enum StoreError: Error, LocalizedError, Equatable {
    case notFound(String)
    case downloadTimedOut(String)
    case accessDenied
    case invalidRecipients(file: String, message: String)

    public var errorDescription: String? {
        switch self {
        case .notFound(let p): "“\(p)” doesn't exist."
        case .downloadTimedOut(let p): "“\(p)” couldn't be downloaded from iCloud. Check your connection and try again."
        case .accessDenied: "Passage no longer has access to the store folder. Choose it again."
        case .invalidRecipients(let file, let message): "\(file) is invalid: \(message)"
        }
    }
}

/// Reads a passage store in a local directory, with file coordination so it cooperates with
/// iCloud Drive and other File Provider apps.
public struct LocalStore: Sendable {
    public let root: URL

    public init(root: URL) {
        self.root = root
    }

    public func url(for entry: EntryPath) -> URL {
        root.appending(path: entry.path + ".age", directoryHint: .notDirectory)
    }

    public func snapshot() async throws -> StoreSnapshot {
        try await coordinated(reading: root, options: .immediatelyAvailableMetadataOnly) { url in
            try StoreSnapshot.scan(root: url)
        }
    }

    /// Reads an entry's ciphertext, downloading it from iCloud first if needed.
    public func read(_ entry: EntryPath) async throws -> Data {
        let url = url(for: entry)
        try await ensureDownloaded(url, displayName: entry.path)
        return try await coordinated(reading: url) { try Data(contentsOf: $0) }
    }

    /// The `.age-recipients` file that applies to `entry`: the nearest one walking up from its
    /// folder to the root, as passage does. Nil if there is none.
    public func recipientsFile(for entry: EntryPath) -> URL? {
        var folder = entry.folder
        while true {
            let candidate = (folder.isEmpty ? root : root.appending(path: folder, directoryHint: .isDirectory))
                .appending(path: ".age-recipients", directoryHint: .notDirectory)
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            if folder.isEmpty { return nil }
            folder = EntryPath(folder).folder
        }
    }

    /// Parses the recipients that apply to `entry`, or returns `[]` if there's no `.age-recipients`.
    public func recipients(for entry: EntryPath) async throws -> [any AgeRecipient] {
        guard let file = recipientsFile(for: entry) else { return [] }
        try await ensureDownloaded(file, displayName: ".age-recipients")
        let text = try await coordinated(reading: file) { try String(contentsOf: $0, encoding: .utf8) }
        do {
            return try RecipientParser.parseFile(text)
        } catch {
            let relative = file.path.replacingOccurrences(of: root.path + "/", with: "")
            throw StoreError.invalidRecipients(file: relative, message: error.localizedDescription)
        }
    }

    // MARK: File coordination

    func coordinated<T: Sendable>(
        reading url: URL, options: NSFileCoordinator.ReadingOptions = [], _ body: @escaping @Sendable (URL) throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let intent = NSFileAccessIntent.readingIntent(with: url, options: options)
            NSFileCoordinator().coordinate(with: [intent], queue: Self.queue) { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(with: Result { try body(intent.url) })
            }
        }
    }

    func coordinated(
        writing url: URL, options: NSFileCoordinator.WritingOptions = [], _ body: @escaping @Sendable (URL) throws -> Void
    ) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let intent = NSFileAccessIntent.writingIntent(with: url, options: options)
            NSFileCoordinator().coordinate(with: [intent], queue: Self.queue) { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(with: Result { try body(intent.url) })
            }
        }
    }

    func coordinated(moving source: URL, to target: URL) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let from = NSFileAccessIntent.writingIntent(with: source, options: .forMoving)
            let to = NSFileAccessIntent.writingIntent(with: target, options: .forReplacing)
            nonisolated(unsafe) let coordinator = NSFileCoordinator()  // used only inside its own callback
            coordinator.coordinate(with: [from, to], queue: Self.queue) { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(with: Result {
                    coordinator.item(at: from.url, willMoveTo: to.url)
                    try FileManager.default.moveItem(at: from.url, to: to.url)
                    coordinator.item(at: from.url, didMoveTo: to.url)
                })
            }
        }
    }

    private static let queue: OperationQueue = {
        let q = OperationQueue()
        q.name = "PassStore.LocalStore"
        q.maxConcurrentOperationCount = 4
        return q
    }()

    private func ensureDownloaded(_ url: URL, displayName: String, timeout: Duration = .seconds(30)) async throws {
        let placeholder = url.deletingLastPathComponent().appending(path: ".\(url.lastPathComponent).icloud")
        let fm = FileManager.default
        guard (try? url.resourceValues(forKeys: [.isUbiquitousItemKey]).isUbiquitousItem) == true
            || fm.fileExists(atPath: placeholder.path)
        else {
            guard fm.fileExists(atPath: url.path) else { throw StoreError.notFound(displayName) }
            return
        }

        func isCurrent() -> Bool {
            let values = try? url.resourceValues(forKeys: [.ubiquitousItemDownloadingStatusKey])
            return values?.ubiquitousItemDownloadingStatus == .current
        }
        if isCurrent() { return }
        try fm.startDownloadingUbiquitousItem(at: url)
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(200))
            if isCurrent() { return }
        }
        throw StoreError.downloadTimedOut(displayName)
    }
}

// MARK: Writing

extension StoreError {
    /// Raised when no `.age-recipients` applies, so there's nobody to encrypt to.
    static func noRecipients(_ entry: EntryPath) -> StoreError {
        .invalidRecipients(file: ".age-recipients", message: "no recipients file applies to “\(entry.path)”. Add one to the store or folder.")
    }
}

extension LocalStore {
    /// Encrypts `plaintext` to the recipients that apply to `entry` and writes it atomically.
    /// Returns the recipients used.
    @discardableResult
    public func save(_ entry: EntryPath, plaintext: Data) async throws -> [any AgeRecipient] {
        let recipients = try await recipients(for: entry)
        guard !recipients.isEmpty else { throw StoreError.noRecipients(entry) }
        let ciphertext = try Age.encrypt(plaintext, to: recipients)
        let url = url(for: entry)
        try await coordinated(writing: url) { url in
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try ciphertext.write(to: url, options: .atomic)
        }
        return recipients
    }

    public func exists(_ entry: EntryPath) -> Bool {
        FileManager.default.fileExists(atPath: url(for: entry).path)
    }

    /// Deletes an entry and any folders it leaves empty.
    public func delete(_ entry: EntryPath) async throws {
        let url = url(for: entry)
        try await coordinated(writing: url, options: .forDeleting) { try FileManager.default.removeItem(at: $0) }
        removeEmptyFolders(from: entry.folder)
    }

    /// Moves an entry. If the destination has different recipients, the entry is decrypted with
    /// `decrypt` and re-encrypted for them, as `passage mv` does.
    public func move(_ from: EntryPath, to: EntryPath, decrypt: @Sendable (Data) async throws -> Data) async throws {
        guard from != to else { return }
        guard !exists(to) else { throw CocoaError(.fileWriteFileExists) }
        let old = try await recipients(for: from).map(\.encoded).sorted()
        let new = try await recipients(for: to).map(\.encoded).sorted()
        if old == new {
            let source = url(for: from), target = url(for: to)
            try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try await coordinated(moving: source, to: target)
        } else {
            let plaintext = try await decrypt(read(from))
            try await save(to, plaintext: plaintext)
            try await delete(from)
        }
        removeEmptyFolders(from: from.folder)
    }

    private func removeEmptyFolders(from folder: String) {
        var folder = folder
        while !folder.isEmpty {
            let url = root.appending(path: folder, directoryHint: .isDirectory)
            guard let contents = try? FileManager.default.contentsOfDirectory(atPath: url.path), contents.isEmpty else { return }
            try? FileManager.default.removeItem(at: url)
            folder = EntryPath(folder).folder
        }
    }
}
