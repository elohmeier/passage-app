import Foundation

/// Strict, canonical base64 (RFC 4648 standard alphabet).
///
/// age headers use the unpadded variant; ASCII armor uses the padded one. Decoding rejects
/// non-alphabet characters (including whitespace and newlines) and non-zero trailing bits, so
/// every byte string has exactly one accepted encoding.
enum Base64 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    private static let reverse: [UInt8] = {
        var table = [UInt8](repeating: 0xFF, count: 256)
        for (i, c) in alphabet.enumerated() {
            table[Int(c)] = UInt8(i)
        }
        return table
    }()

    static func encode(_ data: some Collection<UInt8>, padded: Bool = false) -> String {
        let bytes = Array(data)
        var out = [UInt8]()
        out.reserveCapacity((bytes.count + 2) / 3 * 4)
        var i = 0
        while i + 3 <= bytes.count {
            let n = UInt32(bytes[i]) << 16 | UInt32(bytes[i + 1]) << 8 | UInt32(bytes[i + 2])
            out += [alphabet[Int(n >> 18 & 63)], alphabet[Int(n >> 12 & 63)], alphabet[Int(n >> 6 & 63)], alphabet[Int(n & 63)]]
            i += 3
        }
        switch bytes.count - i {
        case 1:
            let n = UInt32(bytes[i]) << 16
            out += [alphabet[Int(n >> 18 & 63)], alphabet[Int(n >> 12 & 63)]]
            if padded { out += Array("==".utf8) }
        case 2:
            let n = UInt32(bytes[i]) << 16 | UInt32(bytes[i + 1]) << 8
            out += [alphabet[Int(n >> 18 & 63)], alphabet[Int(n >> 12 & 63)], alphabet[Int(n >> 6 & 63)]]
            if padded { out += Array("=".utf8) }
        default:
            break
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func decode(_ string: some StringProtocol, padded: Bool = false) -> Data? {
        decode(Array(string.utf8), padded: padded)
    }

    static func decode(_ input: [UInt8], padded: Bool = false) -> Data? {
        var chars = input[...]
        if padded {
            guard chars.count % 4 == 0 else { return nil }
            var padding = 0
            while padding < 2, chars.last == UInt8(ascii: "=") {
                chars = chars.dropLast()
                padding += 1
            }
            // A third '=' (or a full block of padding) is never canonical.
            if chars.last == UInt8(ascii: "=") { return nil }
            if padding > 0, chars.count % 4 != 4 - padding { return nil }
        }
        guard chars.count % 4 != 1 else { return nil }

        var out = Data()
        out.reserveCapacity(chars.count * 3 / 4)
        var acc: UInt32 = 0
        var bits = 0
        for c in chars {
            let v = reverse[Int(c)]
            guard v != 0xFF else { return nil }
            acc = acc << 6 | UInt32(v)
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: acc >> UInt32(bits)))
                acc &= (1 << UInt32(bits)) - 1
            }
        }
        // Leftover bits must be zero for the encoding to be canonical.
        guard acc == 0 else { return nil }
        return out
    }
}
