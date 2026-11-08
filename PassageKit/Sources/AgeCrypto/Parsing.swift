import Foundation

public enum RecipientParser {
    /// Parses a single recipient string of any natively supported type.
    public static func parse(_ string: String) throws(AgeError) -> any AgeRecipient {
        let s = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("age1pq1") { return try HybridRecipient(s) }
        if s.hasPrefix("age1tag1") || s.hasPrefix("age1tagpq1") || s.hasPrefix("age1se1") || s.hasPrefix("age1yubikey1") {
            return try TagRecipient(s)
        }
        if s.hasPrefix("age1") {
            // The Bech32 data charset has no "1", so a second "1" means a plugin recipient.
            guard let plugin = pluginName(s) else { return try X25519Recipient(s) }
            throw .invalidEncoding("Recipients of the age plugin type \(plugin) are not supported")
        }
        if s.hasPrefix("ssh-") { throw .invalidEncoding("SSH recipients are not supported yet") }
        throw .invalidEncoding("Unknown recipient type")
    }

    /// Parses a recipients file (`.age-recipients`, `-R` file): one recipient per line, `#`
    /// comments and blank lines ignored. Fails on the first invalid line, reporting its number.
    public static func parseFile(_ contents: String) throws(AgeError) -> [any AgeRecipient] {
        var out: [any AgeRecipient] = []
        for (n, line) in contents.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let l = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if l.isEmpty || l.hasPrefix("#") { continue }
            do {
                out.append(try parse(l))
            } catch {
                throw .invalidEncoding("line \(n + 1): \(error.localizedDescription)")
            }
        }
        guard !out.isEmpty else { throw .noRecipients }
        return out
    }

    /// For `age1name1…` plugin recipients, the plugin name.
    static func pluginName(_ s: String) -> String? {
        guard s.hasPrefix("age1"), let sep = s.lastIndex(of: "1"), sep > s.index(s.startIndex, offsetBy: 3) else { return nil }
        return String(s[s.index(s.startIndex, offsetBy: 4)..<sep])
    }
}

public enum IdentityParser {
    /// Parses an identity file (as used by `age -i` and passage's `identities`): native
    /// `AGE-SECRET-KEY-…` lines, `#` comments and blank lines.
    public static func parseFile(_ contents: String) throws(AgeError) -> [any AgeIdentity] {
        var out: [any AgeIdentity] = []
        for (n, line) in contents.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let l = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if l.isEmpty || l.hasPrefix("#") { continue }
            do {
                if l.hasPrefix("AGE-SECRET-KEY-PQ-1") {
                    out.append(try HybridIdentity(l))
                } else if l.hasPrefix("AGE-SECRET-KEY-1") {
                    out.append(try X25519Identity(l))
                } else if l.hasPrefix("AGE-PLUGIN-") {
                    throw AgeError.invalidEncoding("plugin identities can't be imported")
                } else {
                    throw AgeError.invalidEncoding("unknown identity type")
                }
            } catch {
                throw .invalidEncoding("line \(n + 1): \(error.localizedDescription)")
            }
        }
        guard !out.isEmpty else { throw .invalidEncoding("no identities found") }
        return out
    }
}
