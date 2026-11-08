import Foundation

/// Bech32 (BIP 173) without the 90 character limit, as used by age for keys and recipients.
public enum Bech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    private static let generator: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x1ff_ffff) << 5 ^ UInt32(v)
            for i in 0..<5 where (top >> UInt32(i)) & 1 == 1 {
                chk ^= generator[i]
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: [UInt8]) -> [UInt8] {
        hrp.map { $0 >> 5 } + [0] + hrp.map { $0 & 31 }
    }

    private static func convertBits(_ data: some Collection<UInt8>, from: Int, to: Int, pad: Bool) -> [UInt8]? {
        var acc = 0
        var bits = 0
        var out = [UInt8]()
        let maxv = (1 << to) - 1
        for value in data {
            guard Int(value) >> from == 0 else { return nil }
            acc = acc << from | Int(value)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8(acc >> bits & maxv))
            }
        }
        if pad {
            if bits > 0 { out.append(UInt8(acc << (to - bits) & maxv)) }
        } else if bits >= from || (acc << (to - bits)) & maxv != 0 {
            return nil
        }
        return out
    }

    /// Encodes `data` with the given human-readable part. The result is lowercase unless the
    /// HRP is uppercase, in which case the whole string is uppercased (as for age secret keys).
    public static func encode(hrp: String, data: some Collection<UInt8>) -> String {
        let lowerHRP = Array(hrp.lowercased().utf8)
        let values = convertBits(data, from: 8, to: 5, pad: true)!
        let mod = polymod(hrpExpand(lowerHRP) + values + [0, 0, 0, 0, 0, 0]) ^ 1
        let checksum = (0..<6).map { UInt8(mod >> UInt32(5 * (5 - $0)) & 31) }
        let s = String(decoding: lowerHRP + [UInt8(ascii: "1")] + (values + checksum).map { charset[Int($0)] }, as: UTF8.self)
        return hrp == hrp.uppercased() && hrp != hrp.lowercased() ? s.uppercased() : s
    }

    /// Decodes a Bech32 string. The returned HRP keeps the case of the input, so callers can
    /// distinguish `age1…` recipients from `AGE-SECRET-KEY-1…` identities.
    public static func decode(_ string: String) throws(AgeError) -> (hrp: String, data: Data) {
        let bytes = Array(string.utf8)
        guard bytes.allSatisfy({ $0 >= 33 && $0 <= 126 }) else { throw .invalidEncoding("bech32: invalid character") }
        let lower = string.lowercased()
        guard lower == string || string.uppercased() == string else { throw .invalidEncoding("bech32: mixed case") }
        let lowerBytes = Array(lower.utf8)
        guard let sep = lowerBytes.lastIndex(of: UInt8(ascii: "1")), sep >= 1, sep + 7 <= lowerBytes.count else {
            throw .invalidEncoding("bech32: separator '1' at invalid position")
        }
        let hrp = Array(lowerBytes[..<sep])
        var values = [UInt8]()
        for c in lowerBytes[(sep + 1)...] {
            guard let v = charset.firstIndex(of: c) else { throw .invalidEncoding("bech32: invalid character in data part") }
            values.append(UInt8(v))
        }
        guard polymod(hrpExpand(hrp) + values) == 1 else { throw .invalidEncoding("bech32: invalid checksum") }
        guard let data = convertBits(values.dropLast(6), from: 5, to: 8, pad: false) else {
            throw .invalidEncoding("bech32: invalid data padding")
        }
        return (String(string.prefix(sep)), Data(data))
    }
}
