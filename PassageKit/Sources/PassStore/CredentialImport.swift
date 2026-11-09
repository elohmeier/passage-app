import Foundation

/// A credential from another password manager (e.g. Apple Passwords via Credential Exchange),
/// in a neutral form that maps to pass entries.
public struct ImportedItem: Sendable, Equatable {
    public var title: String
    public var urls: [String] = []
    public var userName: String?
    public var password: String?
    public var otp: OTP?
    public var notes: [String] = []
    public var passkeys: [Passkey] = []

    public init(title: String) {
        self.title = title
    }
}

public enum CredentialImport {
    /// Entries for the imported items: logins under `imported/<site>/<user>`, passkeys under
    /// `passkeys/<rp>/<user>`, never overwriting existing entries (a numeric suffix is added).
    public static func entries(for items: [ImportedItem], existing: Set<EntryPath>) -> [(path: EntryPath, text: String)] {
        var taken = existing
        var out: [(EntryPath, String)] = []

        func unique(_ path: String) -> EntryPath {
            var candidate = EntryPath(path)
            var n = 2
            while taken.contains(candidate) {
                candidate = EntryPath("\(path)-\(n)")
                n += 1
            }
            taken.insert(candidate)
            return candidate
        }

        for item in items {
            if item.password != nil || item.otp != nil || !item.notes.isEmpty {
                let site = item.urls.lazy.compactMap(AutoFillIndex.host(of:)).first ?? sanitize(item.title)
                let user = item.userName.map(sanitize).flatMap { $0.isEmpty ? nil : $0 } ?? "login"
                // The first line of an entry is the password; a multi-line one goes into a field
                // instead, so its other lines can't pose as fields.
                let password = item.password ?? ""
                let multiline = password.contains(where: \.isNewline)
                var draft = EntryDraft(password: multiline ? "" : password)
                if multiline { draft.otherFields.append(.init(key: "password", value: password)) }
                if let userName = item.userName { draft.username = userName.filter { !$0.isNewline } }
                if let url = item.urls.first { draft.url = url.filter { !$0.isNewline } }
                draft.otpURI = item.otp?.uri
                if !item.title.isEmpty, item.title.lowercased() != site { draft.otherFields.append(.init(key: "title", value: item.title)) }
                for note in item.notes where !note.isEmpty { draft.otherFields.append(.init(key: "notes", value: note)) }
                out.append((unique("imported/\(site.isEmpty ? "untitled" : site)/\(user)"), draft.text))
            }
            for passkey in item.passkeys {
                out.append((unique(passkey.suggestedPath.path), passkey.entryText))
            }
        }
        return out
    }

    /// A single path component: no slashes, no leading dots, no control characters. Can be
    /// empty.
    static func sanitize(_ s: String) -> String {
        let cleaned = s.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.map(String.init).joined()
            .replacingOccurrences(of: "/", with: "_").trimmingCharacters(in: .whitespaces)
        return String(cleaned.drop { $0 == "." }).lowercased()
    }
}

extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
