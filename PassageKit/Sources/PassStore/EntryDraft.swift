import Foundation

/// An editable entry that serializes back to pass format.
///
/// Field order is kept, so an edit only changes what the user changed. Values with line
/// breaks are written as `key: |` blocks with two-space indentation, which `Entry` reads back.
public struct EntryDraft: Equatable, Sendable {
    public struct Field: Equatable, Sendable, Identifiable {
        public var id = UUID()
        /// Nil for a plain line (a note without a key).
        public var key: String?
        public var value: String

        public init(key: String?, value: String) {
            self.key = key
            self.value = value
        }

        public static func == (a: Self, b: Self) -> Bool { a.key == b.key && a.value == b.value }
    }

    public var password: String
    public var fields: [Field]
    /// An `otpauth://` URI, written on its own line.
    public var otpURI: String?

    public init(password: String = "", fields: [Field] = [], otpURI: String? = nil) {
        self.password = password
        self.fields = fields
        self.otpURI = otpURI
    }

    /// Starts an edit from existing plaintext, read with the same rules as `Entry`.
    /// passforios-style `otp_*` fields are saved back as an equivalent `otpauth://` URI.
    public init(_ text: String) {
        let entry = Entry(text)
        password = entry.password ?? ""
        fields = entry.fields.map { Field(key: $0.key, value: $0.value) }
        otpURI = Self.otpLine(in: text)
        if otpURI == nil, let otp = entry.otp {
            otpURI = otp.uri
        }
    }

    public var username: String {
        get { fields.first { Self.isUsernameKey($0.key) }?.value ?? "" }
        set { setField(newValue, where: Self.isUsernameKey, defaultKey: "username") }
    }

    public var url: String {
        get { fields.first { $0.key?.lowercased() == "url" }?.value ?? "" }
        set { setField(newValue, where: { $0?.lowercased() == "url" }, defaultKey: "url") }
    }

    /// The fields other than username and URL (which have their own inputs in the editor).
    public var otherFields: [Field] {
        get {
            let userIndex = fields.firstIndex { Self.isUsernameKey($0.key) }
            let urlIndex = fields.firstIndex { $0.key?.lowercased() == "url" }
            return fields.enumerated().filter { $0.offset != userIndex && $0.offset != urlIndex }.map(\.element)
        }
        set {
            let primary = [fields.first { Self.isUsernameKey($0.key) }, fields.first { $0.key?.lowercased() == "url" }]
            fields = primary.compactMap { $0 } + newValue
        }
    }

    /// pass format: password, then `key: value` lines, then the OTP URI.
    public var text: String {
        // Only the first line can be the password; more lines would be read as fields.
        var lines = [String(password.prefix { !$0.isNewline })]
        for field in fields where !field.value.isEmpty || field.key != nil {
            let value = field.value.replacingOccurrences(of: "\r\n", with: "\n")
            guard let key = field.key, !key.isEmpty else {
                lines += value.components(separatedBy: "\n").filter { !$0.isEmpty }
                continue
            }
            if value.contains("\n") || value == "|" || value == ">" {
                lines.append("\(key): |")
                lines += value.components(separatedBy: "\n").map { "  " + $0 }
            } else {
                lines.append("\(key): \(value)")
            }
        }
        if let otpURI, !otpURI.isEmpty { lines.append(otpURI) }
        return lines.joined(separator: "\n") + "\n"
    }

    private mutating func setField(_ value: String, where match: (String?) -> Bool, defaultKey: String) {
        if let i = fields.firstIndex(where: { match($0.key) }) {
            if value.isEmpty {
                fields.remove(at: i)
            } else {
                fields[i].value = value
            }
        } else if !value.isEmpty {
            // Username and URL go first, in that order, like most pass entries.
            let insertAt = defaultKey == "url" ? (fields.firstIndex { Self.isUsernameKey($0.key) }.map { $0 + 1 } ?? 0) : 0
            fields.insert(Field(key: defaultKey, value: value), at: insertAt)
        }
    }

    private static func isUsernameKey(_ key: String?) -> Bool {
        ["username", "login", "user"].contains(key?.lowercased() ?? "")
    }

    private static func otpLine(in text: String) -> String? {
        text.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .first { $0.hasPrefix("otpauth://") }
    }
}

extension OTP {
    /// An `otpauth://` URI for this generator.
    public var uri: String {
        var c = URLComponents()
        c.scheme = "otpauth"
        c.host = period != nil ? "totp" : "hotp"
        let label = [issuer, account].compactMap { $0 }.joined(separator: ":")
        c.path = "/" + label
        var items = [URLQueryItem(name: "secret", value: Base32.encode(secret))]
        if let issuer { items.append(URLQueryItem(name: "issuer", value: issuer)) }
        if algorithm != .sha1 { items.append(URLQueryItem(name: "algorithm", value: algorithm.rawValue.uppercased())) }
        if steam {
            items.append(URLQueryItem(name: "encoder", value: "steam"))
        } else if digits != 6 {
            items.append(URLQueryItem(name: "digits", value: String(digits)))
        }
        switch kind {
        case .totp(let p) where p != 30: items.append(URLQueryItem(name: "period", value: String(p)))
        case .hotp(let counter): items.append(URLQueryItem(name: "counter", value: String(counter)))
        default: break
        }
        c.queryItems = items
        return c.string ?? ""
    }
}

extension Base32 {
    static func encode(_ data: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = ""
        var acc: UInt32 = 0
        var bits = 0
        for byte in data {
            acc = acc << 8 | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[Int(acc >> UInt32(bits) & 31)])
            }
        }
        if bits > 0 { out.append(alphabet[Int(acc << UInt32(5 - bits) & 31)]) }
        return out
    }
}
