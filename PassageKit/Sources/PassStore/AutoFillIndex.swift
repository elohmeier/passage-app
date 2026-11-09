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
        /// Set for passkey entries (learned from content: needs the credential ID).
        public var passkey: PasskeyInfo?

        public var id: String { path }

        public init(path: String, domains: [String], username: String?, hasOTP: Bool, fromContent: Bool, passkey: PasskeyInfo? = nil) {
            self.path = path
            self.domains = domains
            self.username = username
            self.hasOTP = hasOTP
            self.fromContent = fromContent
            self.passkey = passkey
        }
    }

    /// What iOS needs to offer a passkey: public identifiers only.
    public struct PasskeyInfo: Codable, Equatable, Sendable {
        public var relyingParty: String
        public var userName: String
        public var credentialID: Data
        public var userHandle: Data
    }

    public var items: [Item]
    /// Passkey credential IDs a website reported as unknown (deleted there). They're hidden
    /// from AutoFill; the entries themselves stay.
    public var staleCredentialIDs: [Data]?

    public init(items: [Item] = []) {
        self.items = items
    }

    public func isStale(_ item: Item) -> Bool {
        guard let id = item.passkey?.credentialID else { return false }
        return staleCredentialIDs?.contains(id) ?? false
    }

    /// Signal API: the site doesn't know this credential anymore.
    public mutating func markUnknown(relyingParty: String, credentialID: Data) {
        guard items.contains(where: { $0.passkey?.credentialID == credentialID && $0.passkey?.relyingParty.lowercased() == relyingParty.lowercased() })
        else { return }
        staleCredentialIDs = Array(Set((staleCredentialIDs ?? []) + [credentialID]))
    }

    /// Signal API: the complete list of credentials the site accepts for this user.
    public mutating func markAccepted(relyingParty: String, userHandle: Data, accepted: [Data]) {
        let ours = items.compactMap(\.passkey).filter { $0.relyingParty.lowercased() == relyingParty.lowercased() && $0.userHandle == userHandle }
        let rejected = ours.map(\.credentialID).filter { !accepted.contains($0) }
        var stale = Set(staleCredentialIDs ?? []).subtracting(accepted)
        stale.formUnion(rejected)
        staleCredentialIDs = stale.isEmpty ? nil : Array(stale)
    }

    /// Signal API: the site renamed the account; update what AutoFill shows.
    public mutating func rename(relyingParty: String, userHandle: Data, to name: String) {
        for i in items.indices where items[i].passkey?.relyingParty.lowercased() == relyingParty.lowercased() && items[i].passkey?.userHandle == userHandle {
            items[i].passkey?.userName = name
        }
    }

    /// Rebuilds the index for `entries`: content-derived items are kept for entries that still
    /// exist, everything else is guessed from the path.
    public func updated(for entries: [EntryPath]) -> AutoFillIndex {
        let known = Dictionary(items.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var index = AutoFillIndex(items: entries.map { entry in
            if let item = known[entry.path], item.fromContent { return item }
            return Self.guess(entry)
        })
        index.staleCredentialIDs = staleCredentialIDs
        return index
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
        if let passkey = Passkey(entry: content) {
            item.passkey = PasskeyInfo(
                relyingParty: passkey.relyingParty, userName: passkey.userName, credentialID: passkey.credentialID,
                userHandle: passkey.userHandle)
            item.domains = [passkey.relyingParty] + item.domains.filter { $0 != passkey.relyingParty }
        }
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
    /// Passkey items for a relying party, optionally limited to the credential IDs the site
    /// allows. Passkeys are bound to their exact RP ID, so no subdomain matching here.
    public static func passkeys(_ items: [AutoFillIndex.Item], relyingParty: String, allowed: [Data] = [], stale: [Data] = []) -> [AutoFillIndex.Item] {
        items.filter { item in
            if let id = item.passkey?.credentialID, stale.contains(id) { return false }
            guard let p = item.passkey, p.relyingParty.lowercased() == relyingParty.lowercased() else { return false }
            return allowed.isEmpty || allowed.contains(p.credentialID)
        }
    }

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
