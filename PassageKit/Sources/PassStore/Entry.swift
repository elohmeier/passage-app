import Foundation

/// A decrypted pass entry.
///
/// The format follows pass conventions, compatible with passforios:
///
///     password
///     username: alice
///     url: https://example.com
///     otpauth://totp/Example:alice?secret=…
///     notes: |
///       indented lines form a multiline value
///
/// The first line is the password. Every other non-empty line is a `key: value` field; lines
/// without `": "` become unnamed fields. A value of `|` (keep line breaks) or `>` (fold into one
/// line) collects the following lines that share the first one's indentation.
public struct Entry: Equatable, Sendable {
    public struct Field: Equatable, Sendable, Identifiable {
        /// Nil for lines that aren't `key: value`.
        public let key: String?
        public let value: String
        public let id: Int

        /// Fields that look secret are concealed by default in the UI.
        public var isSensitive: Bool {
            guard let k = key?.lowercased() else { return false }
            return ["pass", "pin", "secret", "cvv", "cvc", "puk", "token", "recovery"].contains { k.contains($0) }
        }
    }

    /// The first line, or nil if the first line is an `otpauth://` URI (an OTP-only entry).
    public let password: String?
    /// All fields except OTP ones, in file order.
    public let fields: [Field]
    public let otp: OTP?

    public init(_ text: String) {
        var lines = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        let first = lines.isEmpty ? "" : lines.removeFirst()

        var parsed: [(key: String?, value: String)] = []
        var otpLine: String?
        if first.hasPrefix("otpauth://") {
            password = nil
            otpLine = first
        } else {
            password = first
        }

        let rest = lines.filter { !$0.isEmpty }
        var i = 0
        while i < rest.count {
            let line = rest[i]
            i += 1
            if line.hasPrefix("otpauth://") {
                otpLine = otpLine ?? line
                continue
            }
            guard let sep = line.range(of: ": ") else {
                parsed.append((nil, line))
                continue
            }
            let key = line[..<sep.lowerBound].trimmingCharacters(in: .whitespaces)
            var value = line[sep.upperBound...].trimmingCharacters(in: .whitespaces)
            if key.isEmpty {
                parsed.append((nil, line))
                continue
            }
            if value == "|" || value == ">" {
                value = Self.multiline(rest, from: &i, keepLineBreaks: value == "|")
            }
            parsed.append((key, value))
        }

        var otpFields: [String: String] = [:]
        var fields: [Field] = []
        for (key, value) in parsed {
            if let key, key.lowercased() == "otpauth" || key.lowercased().hasPrefix("otp_") {
                if key.lowercased() == "otpauth" {
                    otpLine = otpLine ?? (value.hasPrefix("otpauth:") ? value : "otpauth:" + value)
                } else {
                    otpFields[key.lowercased()] = value
                }
                continue
            }
            fields.append(Field(key: key, value: value, id: fields.count))
        }
        self.fields = fields
        otp = otpLine.flatMap(OTP.init(uri:)) ?? OTP(fields: otpFields)
    }

    private static func multiline(_ lines: [String], from i: inout Int, keepLineBreaks: Bool) -> String {
        guard i < lines.count else { return "" }
        let indent = lines[i].prefix { $0 == " " }.count
        guard indent > 0 else { return "" }
        let prefix = String(repeating: " ", count: indent)
        var parts: [String] = []
        while i < lines.count, lines[i].hasPrefix(prefix) {
            parts.append(String(lines[i].dropFirst(indent)))
            i += 1
        }
        return parts.joined(separator: keepLineBreaks ? "\n" : " ").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The first of `username`, `login`, `user` (case-insensitive).
    public var username: String? {
        for name in ["username", "login", "user"] {
            if let f = fields.first(where: { $0.key?.lowercased() == name }) { return f.value }
        }
        return nil
    }

    public var url: String? {
        fields.first { $0.key?.lowercased() == "url" }?.value
    }
}
