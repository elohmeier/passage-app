import Foundation

/// What AutoFill knows about each entry without decrypting it: domains and username from the
/// path, refined with `url:` / `username:` from entries the user has decrypted. Contains no
/// secrets; stored with complete file protection.
public struct AutoFillIndex: Codable, Equatable, Sendable {
    public struct Item: Codable, Equatable, Sendable, Identifiable {
        public var path: String
        public var domains: [String]
        public var username: String?
        public var hasOTP: Bool
        /// True once filled in from the decrypted entry rather than guessed from the path.
        public var fromContent: Bool

        public var id: String { path }
    }

    public var items: [Item]

    public init(items: [Item] = []) {
        self.items = items
    }

    /// Rebuilds the index for `entries`: content-derived items are kept for entries that still
    /// exist, everything else is guessed from the path.
    public func updated(for entries: [EntryPath]) -> AutoFillIndex {
        let known = Dictionary(items.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        return AutoFillIndex(items: entries.map { entry in
            if let item = known[entry.path], item.fromContent { return item }
            return Self.guess(entry)
        })
    }

    /// Records what a decrypted entry says about itself.
    public mutating func learn(_ entry: EntryPath, from content: Entry) {
        var item = Self.guess(entry)
        if let host = content.url.flatMap(Self.host(of:)) {
            item.domains = [host] + item.domains.filter { $0 != host }
        }
        if let username = content.username { item.username = username }
        item.hasOTP = content.otp != nil
        item.fromContent = true
        if let i = items.firstIndex(where: { $0.path == entry.path }) {
            items[i] = item
        } else {
            items.append(item)
        }
    }

    public mutating func forget(_ entry: EntryPath) {
        items.removeAll { $0.path == entry.path }
    }

    /// Path heuristics: any component that looks like a host name is a domain; if the entry
    /// sits directly inside such a folder (`github.com/alice`), its name is the username.
    static func guess(_ entry: EntryPath) -> Item {
        let components = entry.path.split(separator: "/").map(String.init)
        let domains = components.compactMap(normalizedHost)
        var username: String?
        if components.count >= 2, normalizedHost(components[components.count - 2]) != nil, normalizedHost(components.last!) == nil {
            username = components.last
        }
        return Item(path: entry.path, domains: domains, username: username, hasOTP: false, fromContent: false)
    }

    static func host(of url: String) -> String? {
        let withScheme = url.contains("://") ? url : "https://" + url
        return URLComponents(string: withScheme)?.host.flatMap(normalizedHost)
    }

    /// Lowercased host name if `s` looks like one (has a dot, valid characters, a letter TLD).
    static func normalizedHost(_ s: String) -> String? {
        let h = s.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let labels = h.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" } }),
            let tld = labels.last, tld.count >= 2, tld.allSatisfy(\.isLetter)
        else { return nil }
        return h
    }
}

public enum AutoFillMatcher {
    /// Items matching a website or app's associated domain, best first: exact host, then the
    /// entry's domain as a parent of the host. Matching is on label boundaries, so
    /// `github.com` matches `gist.github.com` but never `evilgithub.com`.
    public static func match(_ items: [AutoFillIndex.Item], service: String) -> [AutoFillIndex.Item] {
        guard let host = AutoFillIndex.host(of: service) ?? AutoFillIndex.normalizedHost(service) else { return [] }
        let hostWithoutWWW = host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
        var scored: [(AutoFillIndex.Item, Int)] = []
        for item in items {
            var best = 0
            for domain in item.domains {
                let d = domain.hasPrefix("www.") ? String(domain.dropFirst(4)) : domain
                if d == hostWithoutWWW {
                    best = max(best, 3)
                } else if hostWithoutWWW.hasSuffix("." + d) {
                    best = max(best, 2)
                } else if d.hasSuffix("." + hostWithoutWWW) {
                    // Entry for a subdomain (accounts.example.com) offered on example.com.
                    best = max(best, 1)
                }
            }
            if best > 0 { scored.append((item, best + (item.fromContent ? 1 : 0))) }
        }
        return scored.sorted { $0.1 != $1.1 ? $0.1 > $1.1 : $0.0.path < $1.0.path }.map(\.0)
    }
}
