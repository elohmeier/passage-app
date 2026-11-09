import Foundation

/// Who a store encrypts to, per `.age-recipients`, so changes made elsewhere (a pull, another
/// device in the same iCloud folder) can be shown to the user before this device encrypts new
/// entries to them.
public struct RecipientSet: Codable, Equatable, Sendable {
    /// Folder (empty for the root) → recipients, in file order.
    public var folders: [String: [String]]

    public init(folders: [String: [String]]) {
        self.folders = folders
    }

    public struct Change: Equatable, Sendable, Identifiable {
        public var folder: String
        public var added: [Labeled]
        public var removed: [String]
        public var id: String { folder }
    }

    public struct Labeled: Equatable, Sendable {
        public var recipient: String
        /// The comment line above it, e.g. "# Alice's laptop".
        public var label: String?
    }

    /// What changed from `approved` to `self`. `labels` comes from `labels(in:)`.
    public func changes(since approved: RecipientSet, labels: [String: [String: String]] = [:]) -> [Change] {
        Set(folders.keys).union(approved.folders.keys).sorted().compactMap { folder in
            let now = folders[folder] ?? [], before = approved.folders[folder] ?? []
            let added = now.filter { !before.contains($0) }.map { Labeled(recipient: $0, label: labels[folder]?[$0]) }
            let removed = before.filter { !now.contains($0) }
            return added.isEmpty && removed.isEmpty ? nil : Change(folder: folder, added: added, removed: removed)
        }
    }

    /// Recipients and their comment labels from a `.age-recipients` file.
    public static func parse(_ text: String) -> (recipients: [String], labels: [String: String]) {
        var recipients: [String] = [], labels: [String: String] = [:]
        var comment: String?
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty {
                comment = nil
            } else if line.hasPrefix("#") {
                comment = line.dropFirst().trimmingCharacters(in: .whitespaces)
            } else {
                recipients.append(line)
                if let comment { labels[line] = comment }
                comment = nil  // a comment labels the line right below it
            }
        }
        return (recipients, labels)
    }
}

extension LocalStore {
    /// The current recipients of every `.age-recipients`, with their labels.
    public func recipientSet() async throws -> (set: RecipientSet, labels: [String: [String: String]]) {
        var folders: [String: [String]] = [:], labels: [String: [String: String]] = [:]
        for folder in recipientsFiles() {
            let url = (folder.isEmpty ? root : root.appending(path: folder, directoryHint: .isDirectory)).appending(path: ".age-recipients")
            let text = try await coordinated(reading: url) { try String(contentsOf: $0, encoding: .utf8) }
            let parsed = RecipientSet.parse(text)
            folders[folder] = parsed.recipients
            labels[folder] = parsed.labels
        }
        return (RecipientSet(folders: folders), labels)
    }
}
