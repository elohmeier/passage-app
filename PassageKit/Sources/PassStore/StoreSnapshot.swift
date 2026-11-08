import Foundation

/// An entry's location in the store: its path relative to the root, without `.age`.
public struct EntryPath: Hashable, Comparable, Sendable, Identifiable, CustomStringConvertible {
    /// e.g. `email/work/alice`.
    public let path: String

    public init(_ path: String) {
        self.path = path
    }

    public var id: String { path }
    public var description: String { path }
    public var name: String { path.split(separator: "/").last.map(String.init) ?? path }
    /// e.g. `email/work`, or `""` at the root.
    public var folder: String {
        guard let slash = path.lastIndex(of: "/") else { return "" }
        return String(path[..<slash])
    }

    public static func < (a: Self, b: Self) -> Bool {
        a.path.localizedStandardCompare(b.path) == .orderedAscending
    }
}

/// An immutable listing of a store's entries and folders.
public struct StoreSnapshot: Equatable, Sendable {
    public let entries: [EntryPath]
    /// Every folder that contains entries (directly or deeper), without the root.
    public let folders: [String]

    public init(entries: [EntryPath]) {
        self.entries = entries.sorted()
        var folders = Set<String>()
        for entry in entries {
            var f = entry.folder
            while !f.isEmpty {
                guard folders.insert(f).inserted else { break }
                f = EntryPath(f).folder
            }
        }
        self.folders = folders.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    public static let empty = StoreSnapshot(entries: [])

    /// The direct children of `folder` (`""` for the root).
    public func contents(of folder: String) -> (folders: [String], entries: [EntryPath]) {
        (folders.filter { EntryPath($0).folder == folder }, entries.filter { $0.folder == folder })
    }

    /// Entries matching all whitespace-separated terms (case- and diacritic-insensitive),
    /// best matches first: name prefix, then name contains, then path contains.
    public func search(_ query: String) -> [EntryPath] {
        let terms = query.split(whereSeparator: \.isWhitespace).map { $0.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil) }
        guard !terms.isEmpty else { return entries }
        func fold(_ s: String) -> String { s.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil) }

        var scored: [(EntryPath, Int)] = []
        for entry in entries {
            let path = fold(entry.path)
            guard terms.allSatisfy(path.contains) else { continue }
            let name = fold(entry.name)
            let score = terms.reduce(0) { s, t in s + (name.hasPrefix(t) ? 3 : name.contains(t) ? 2 : 1) }
            scored.append((entry, score))
        }
        return scored.sorted { $0.1 != $1.1 ? $0.1 > $1.1 : $0.0 < $1.0 }.map(\.0)
    }

    /// Lists `root`. Hidden directories (`.git`, `.extensions`, …) are skipped. iCloud
    /// placeholders of not-yet-downloaded files (`.name.age.icloud`) count as entries.
    public static func scan(root: URL) throws -> StoreSnapshot {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [],
            errorHandler: { _, _ in true })
        else { throw CocoaError(.fileReadNoSuchFile) }

        let rootComponents = root.standardizedFileURL.resolvingSymlinksInPath().pathComponents.count
        var entries: [EntryPath] = []
        for case let url as URL in enumerator {
            let name = url.lastPathComponent
            let isDirectory = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            if isDirectory {
                if name.hasPrefix(".") { enumerator.skipDescendants() }
                continue
            }
            var fileName = name
            if fileName.hasPrefix("."), fileName.hasSuffix(".icloud") {
                fileName = String(fileName.dropFirst().dropLast(".icloud".count))
            }
            guard fileName.hasSuffix(".age"), !fileName.hasPrefix(".") else { continue }

            let components = url.standardizedFileURL.resolvingSymlinksInPath().pathComponents.dropFirst(rootComponents).dropLast()
            let relative = (Array(components) + [String(fileName.dropLast(4))]).joined(separator: "/")
            entries.append(EntryPath(relative))
        }
        return StoreSnapshot(entries: entries)
    }
}
