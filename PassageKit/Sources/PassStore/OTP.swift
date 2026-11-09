import CryptoKit
import Foundation

/// A one-time password generator (RFC 4226 HOTP, RFC 6238 TOTP, and Steam Guard codes).
public struct OTP: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case totp(period: Int)
        case hotp(counter: UInt64)
    }

    public enum Algorithm: String, Sendable {
        case sha1, sha256, sha512
    }

    public let kind: Kind
    public let secret: Data
    public let algorithm: Algorithm
    public let digits: Int
    /// Steam Guard: 5 characters from a custom alphabet instead of decimal digits.
    public let steam: Bool
    public let issuer: String?
    public let account: String?

    public init(
        kind: Kind, secret: Data, algorithm: Algorithm = .sha1, digits: Int = 6, steam: Bool = false,
        issuer: String? = nil, account: String? = nil
    ) {
        // Values come from entry files; out-of-range ones would crash or produce nonsense.
        if case .totp(let period) = kind, !Self.periods.contains(period) {
            self.kind = .totp(period: 30)
        } else {
            self.kind = kind
        }
        self.secret = secret
        self.algorithm = algorithm
        self.digits = (1...10).contains(digits) ? digits : 6
        self.steam = steam
        self.issuer = issuer
        self.account = account
    }

    static let periods = 1...86_400

    /// Parses an `otpauth://totp/Label?secret=…&issuer=…&algorithm=…&digits=…&period=…` URI.
    /// `otpauth://steam/…` and `encoder=steam` select Steam Guard codes.
    public init?(uri: String) {
        guard let c = URLComponents(string: uri.trimmingCharacters(in: .whitespaces)), c.scheme?.lowercased() == "otpauth",
            let type = c.host?.lowercased()
        else { return nil }
        var q: [String: String] = [:]
        for item in c.queryItems ?? [] {
            q[item.name.lowercased()] = item.value
        }
        guard let secret = q["secret"].flatMap(Base32.decode), !secret.isEmpty else { return nil }

        let label = c.path.hasPrefix("/") ? String(c.path.dropFirst()) : c.path
        let labelParts = label.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        let steam = type == "steam" || q["encoder"]?.lowercased() == "steam"

        let kind: Kind
        switch type {
        case "totp", "steam":
            kind = .totp(period: q["period"].flatMap(Int.init) ?? 30)
        case "hotp":
            guard let counter = q["counter"].flatMap(UInt64.init) else { return nil }
            kind = .hotp(counter: counter)
        default:
            return nil
        }
        self.init(
            kind: kind, secret: secret, algorithm: q["algorithm"].flatMap { Algorithm(rawValue: $0.lowercased()) } ?? .sha1,
            digits: steam ? 5 : q["digits"].flatMap(Int.init) ?? 6, steam: steam,
            issuer: q["issuer"] ?? (labelParts.count == 2 ? labelParts[0] : nil),
            account: labelParts.last.flatMap { $0.isEmpty ? nil : $0 })
    }

    /// Builds a generator from passforios-style `otp_*` fields (keys lowercased).
    init?(fields: [String: String]) {
        guard let secret = fields["otp_secret"].flatMap(Base32.decode), !secret.isEmpty else { return nil }
        let kind: Kind
        switch fields["otp_type"]?.lowercased() ?? "totp" {
        case "totp": kind = .totp(period: fields["otp_period"].flatMap { Double($0) }.flatMap { $0.isFinite && Double(Self.periods.upperBound) >= $0 ? Int($0) : nil } ?? 30)
        case "hotp":
            guard let counter = fields["otp_counter"].flatMap(UInt64.init) else { return nil }
            kind = .hotp(counter: counter)
        default: return nil
        }
        let steam = fields["otp_representation"]?.lowercased() == "steamguard"
        self.init(
            kind: kind, secret: secret, algorithm: fields["otp_algorithm"].flatMap { Algorithm(rawValue: $0.lowercased()) } ?? .sha1,
            digits: steam ? 5 : fields["otp_digits"].flatMap(Int.init) ?? 6, steam: steam)
    }

    public var period: Int? {
        if case .totp(let p) = kind { return p }
        return nil
    }

    /// The TOTP code at `date`, or the HOTP code for the current counter.
    public func code(at date: Date = .now) -> String {
        switch kind {
        case .totp(let period): code(counter: UInt64(max(0, date.timeIntervalSince1970)) / UInt64(max(1, period)))
        case .hotp(let counter): code(counter: counter)
        }
    }

    /// Seconds until the TOTP code changes.
    public func secondsRemaining(at date: Date = .now) -> Double? {
        guard let period else { return nil }
        let p = Double(max(1, period))
        return p - date.timeIntervalSince1970.truncatingRemainder(dividingBy: p)
    }

    public func code(counter: UInt64) -> String {
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: Data = switch algorithm {
        case .sha1: Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(mac[mac.count - 1] & 0x0F)
        var value = (UInt32(mac[offset] & 0x7F) << 24) | (UInt32(mac[offset + 1]) << 16) | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])

        if steam {
            let alphabet = Array("23456789BCDFGHJKMNPQRTVWXY")
            var out = ""
            for _ in 0..<5 {
                out.append(alphabet[Int(value % UInt32(alphabet.count))])
                value /= UInt32(alphabet.count)
            }
            return out
        }
        var mod: UInt32 = 1
        for _ in 0..<min(digits, 9) { mod *= 10 }
        let s = String(value % mod)
        return String(repeating: "0", count: max(0, digits - s.count)) + s
    }
}

/// RFC 4648 base32, lenient about case, spaces, dashes and padding (as users paste secrets).
enum Base32 {
    static func decode(_ string: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var acc: UInt64 = 0
        var bits = 0
        var out = Data()
        for c in string.uppercased().utf8 where c != UInt8(ascii: " ") && c != UInt8(ascii: "-") && c != UInt8(ascii: "=") {
            guard let v = alphabet.firstIndex(of: c) else { return nil }
            acc = acc << 5 | UInt64(v)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: acc >> UInt64(bits)))
                acc &= (1 << UInt64(bits)) - 1
            }
        }
        return out
    }
}
