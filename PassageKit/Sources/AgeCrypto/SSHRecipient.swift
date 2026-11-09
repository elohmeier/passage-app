import CryptoKit
import Foundation
import Security

// SSH public keys as age recipients (encryption only), as in filippo.io/age/agessh. Passage
// users often list `ssh-ed25519` / `ssh-rsa` keys in .age-recipients.

private let ed25519Label = "age-encryption.org/v1/ssh-ed25519"
private let rsaLabel = "age-encryption.org/v1/ssh-rsa"

/// `ssh-ed25519 AAAA… [comment]`.
public struct SSHEd25519Recipient: AgeRecipient {
    /// The SSH wire encoding of the public key.
    let wire: Data
    let montgomery: Data

    public init(_ line: String) throws(AgeError) {
        let (type, wire) = try parseSSHKeyLine(line)
        guard type == "ssh-ed25519" else { throw .invalidEncoding("not an ssh-ed25519 key") }
        var reader = SSHWireReader(wire)
        guard reader.string() == Data("ssh-ed25519".utf8), let key = reader.string(), key.count == 32, reader.atEnd else {
            throw .invalidEncoding("malformed ssh-ed25519 key")
        }
        guard let u = Field25519.montgomeryU(fromEdwardsY: key) else { throw .invalidEncoding("invalid Ed25519 public key") }
        self.wire = wire
        montgomery = u
    }

    public var encoded: String { "ssh-ed25519 " + wire.base64EncodedString() }

    public func wrap(fileKey: Data) throws(AgeError) -> [Stanza] {
        do {
            let ephemeral = Curve25519.KeyAgreement.PrivateKey()
            let share = ephemeral.publicKey.rawRepresentation
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: .init(rawRepresentation: montgomery)).withUnsafeBytes { Data($0) }
            // tweak = HKDF(ikm: "", salt: ssh key, info: label); shared = X25519(tweak, shared)
            let tweak = Primitives.hkdf(ikm: Data(), salt: wire, info: ed25519Label).data
            let tweaked = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: tweak)
                .sharedSecretFromKeyAgreement(with: .init(rawRepresentation: shared)).withUnsafeBytes { Data($0) }
            let key = Primitives.hkdf(ikm: tweaked, salt: share + montgomery, info: ed25519Label)
            return [Stanza(
                type: "ssh-ed25519", args: [sshTag(wire), Base64.encode(share)],
                body: try Primitives.aeadEncrypt(key: key, plaintext: fileKey))]
        } catch let error as AgeError {
            throw error
        } catch {
            throw .invalidEncoding("ssh-ed25519 wrap failed: \(error)")
        }
    }
}

/// `ssh-rsa AAAA… [comment]`, at least 2048 bits.
public struct SSHRSARecipient: AgeRecipient {
    let wire: Data
    /// PKCS#1 DER; the SecKey is created per use because SecKey isn't Sendable.
    let der: Data
    let modulusBytes: Int

    public init(_ line: String) throws(AgeError) {
        let (type, wire) = try parseSSHKeyLine(line)
        guard type == "ssh-rsa" else { throw .invalidEncoding("not an ssh-rsa key") }
        var reader = SSHWireReader(wire)
        guard reader.string() == Data("ssh-rsa".utf8), let e = reader.string(), let n = reader.string(), reader.atEnd else {
            throw .invalidEncoding("malformed ssh-rsa key")
        }
        let modulus = n.drop { $0 == 0 }
        guard modulus.count * 8 >= 2048 else { throw .invalidEncoding("RSA key size is too small") }
        // Like age: an odd public exponent of at least 3 (e = 1 would send the file key in the clear).
        let exponent = e.drop { $0 == 0 }
        guard let last = exponent.last, last & 1 == 1, exponent.count > 1 || last >= 3, exponent.count <= 4 else {
            throw .invalidEncoding("invalid RSA public exponent")
        }
        // PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let der = DER.sequence(DER.integer(n) + DER.integer(e))
        guard Self.secKey(der) != nil else { throw .invalidEncoding("invalid RSA public key") }
        self.wire = wire
        self.der = der
        modulusBytes = modulus.count
    }

    public var encoded: String { "ssh-rsa " + wire.base64EncodedString() }

    public func wrap(fileKey: Data) throws(AgeError) -> [Stanza] {
        // Security.framework's OAEP doesn't take a label, so pad here and use raw RSA.
        let encoded = OAEP.encode(fileKey, label: Data(rsaLabel.utf8), modulusBytes: modulusBytes)
        var error: Unmanaged<CFError>?
        guard let key = Self.secKey(der),
            let ciphertext = SecKeyCreateEncryptedData(key, .rsaEncryptionRaw, encoded as CFData, &error) as Data?
        else {
            throw .invalidEncoding("RSA encryption failed")
        }
        return [Stanza(type: "ssh-rsa", args: [sshTag(wire)], body: ciphertext)]
    }

    private static func secKey(_ der: Data) -> SecKey? {
        SecKeyCreateWithData(der as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, nil)
    }
}

/// `SHA-256(ssh wire key)[:4]`, base64.
private func sshTag(_ wire: Data) -> String {
    Base64.encode(Data(SHA256.hash(data: wire).prefix(4)))
}

private func parseSSHKeyLine(_ line: String) throws(AgeError) -> (type: String, wire: Data) {
    let parts = line.split(separator: " ", omittingEmptySubsequences: true)
    guard parts.count >= 2, let wire = Data(base64Encoded: String(parts[1])) else { throw .invalidEncoding("malformed SSH public key") }
    return (String(parts[0]), wire)
}

struct SSHWireReader {
    private var data: Data
    init(_ data: Data) { self.data = data }
    var atEnd: Bool { data.isEmpty }

    mutating func string() -> Data? {
        guard data.count >= 4 else { return nil }
        let len = data.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        guard data.count >= 4 + len else { return nil }
        let s = Data(data.dropFirst(4).prefix(len))
        data = Data(data.dropFirst(4 + len))
        return s
    }
}

enum DER {
    static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    /// A non-negative INTEGER from big-endian bytes (an SSH mpint is already in this form).
    static func integer(_ value: Data) -> Data {
        var v = Data(value.drop { $0 == 0 })
        if v.isEmpty { v = Data([0]) }
        if v.first! & 0x80 != 0 { v.insert(0, at: 0) }
        return Data([0x02]) + length(v.count) + v
    }

    static func sequence(_ content: Data) -> Data {
        Data([0x30]) + length(content.count) + content
    }
}

/// RSAES-OAEP encoding with SHA-256 and MGF1-SHA-256 (RFC 8017 §7.1.1).
enum OAEP {
    static func encode(_ message: Data, label: Data, modulusBytes k: Int, seed: Data = Primitives.randomBytes(32)) -> Data {
        let hLen = 32
        let lHash = Data(SHA256.hash(data: label))
        let ps = Data(count: k - message.count - 2 * hLen - 2)
        let db = lHash + ps + Data([0x01]) + message
        let maskedDB = xor(db, mgf1(seed, length: k - hLen - 1))
        let maskedSeed = xor(seed, mgf1(maskedDB, length: hLen))
        return Data([0x00]) + maskedSeed + maskedDB
    }

    static func mgf1(_ seed: Data, length: Int) -> Data {
        var out = Data()
        var counter: UInt32 = 0
        while out.count < length {
            out += SHA256.hash(data: seed + withUnsafeBytes(of: counter.bigEndian) { Data($0) })
            counter += 1
        }
        return out.prefix(length)
    }

    private static func xor(_ a: Data, _ b: Data) -> Data {
        Data(zip(a, b).map { $0 ^ $1 })
    }
}

/// Just enough arithmetic mod p = 2^255 - 19 to map an Ed25519 public key to its X25519
/// (Montgomery) form: u = (1 + y) / (1 - y).
enum Field25519 {
    typealias Element = [UInt64]  // 4 little-endian limbs, fully reduced

    static let p: Element = [0xFFFF_FFFF_FFFF_FFED, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF]

    static func montgomeryU(fromEdwardsY encoded: Data) -> Data? {
        var bytes = [UInt8](encoded)
        let xNegative = bytes[31] & 0x80 != 0
        bytes[31] &= 0x7F  // drop the sign of x
        var y = Element(repeating: 0, count: 4)
        for i in 0..<32 {
            y[i / 8] |= UInt64(bytes[i]) << UInt64(8 * (i % 8))
        }
        guard less(y, p), isOnCurve(y: y, xNegative: xNegative) else { return nil }
        let one: Element = [1, 0, 0, 0]
        let denominator = sub(one, y)
        guard denominator != [0, 0, 0, 0] else { return nil }  // y = 1 is the identity
        let u = mul(add(one, y), invert(denominator))
        var out = Data(count: 32)
        for i in 0..<32 {
            out[i] = UInt8(truncatingIfNeeded: u[i / 8] >> UInt64(8 * (i % 8)))
        }
        return out
    }

    static func less(_ a: Element, _ b: Element) -> Bool {
        for i in (0..<4).reversed() where a[i] != b[i] { return a[i] < b[i] }
        return false
    }

    static func reduceOnce(_ a: Element) -> Element {
        less(a, p) ? a : subRaw(a, p)
    }

    static func subRaw(_ a: Element, _ b: Element) -> Element {
        var out = Element(repeating: 0, count: 4)
        var borrow: UInt64 = 0
        for i in 0..<4 {
            let (d1, o1) = a[i].subtractingReportingOverflow(b[i])
            let (d2, o2) = d1.subtractingReportingOverflow(borrow)
            out[i] = d2
            borrow = (o1 || o2) ? 1 : 0
        }
        return out
    }

    static func add(_ a: Element, _ b: Element) -> Element {
        var out = Element(repeating: 0, count: 4)
        var carry: UInt64 = 0
        for i in 0..<4 {
            let (s1, o1) = a[i].addingReportingOverflow(b[i])
            let (s2, o2) = s1.addingReportingOverflow(carry)
            out[i] = s2
            carry = (o1 || o2) ? 1 : 0
        }
        // a, b < p < 2^255, so the sum fits in 256 bits.
        return reduceOnce(out)
    }

    static func sub(_ a: Element, _ b: Element) -> Element {
        less(a, b) ? add(a, subRaw(p, b)) : subRaw(a, b)
    }

    static func mul(_ a: Element, _ b: Element) -> Element {
        var wide = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let product = UInt128(a[i]) * UInt128(b[j]) + UInt128(wide[i + j]) + UInt128(carry)
                wide[i + j] = UInt64(truncatingIfNeeded: product)
                carry = UInt64(truncatingIfNeeded: product >> 64)
            }
            wide[i + 4] = carry
        }
        // 2^256 ≡ 38 (mod p): fold the high half in, twice.
        var out = Element(repeating: 0, count: 4)
        var carry: UInt128 = 0
        for i in 0..<4 {
            let v = UInt128(wide[i]) + UInt128(wide[i + 4]) * 38 + carry
            out[i] = UInt64(truncatingIfNeeded: v)
            carry = v >> 64
        }
        var top = carry * 38
        for i in 0..<4 {
            let v = UInt128(out[i]) + top
            out[i] = UInt64(truncatingIfNeeded: v)
            top = v >> 64
        }
        if top > 0 {
            // Wrapped past 2^256, so `out` is tiny: adding 2^256 ≡ 38 can't overflow again.
            var c: UInt64 = 38
            for i in 0..<4 where c > 0 {
                let (s, o) = out[i].addingReportingOverflow(c)
                out[i] = s
                c = o ? 1 : 0
            }
        }
        // out < 2^256 = 2p + 38, so at most two subtractions of p remain.
        return reduceOnce(reduceOnce(out))
    }

    /// a^(p-2) by square-and-multiply.
    static func invert(_ a: Element) -> Element {
        pow(a, subRaw(p, [2, 0, 0, 0]))
    }

    static func pow(_ a: Element, _ exponent: Element) -> Element {
        var result: Element = [1, 0, 0, 0]
        for i in (0..<256).reversed() {
            result = mul(result, result)
            if exponent[i / 64] >> UInt64(i % 64) & 1 == 1 { result = mul(result, a) }
        }
        return result
    }

    /// Whether some x satisfies -x² + y² = 1 + d·x²·y², i.e. x² = (y² - 1) / (d·y² + 1) is a
    /// square (Euler's criterion), as Ed25519 point decoding requires. x = 0 must not be
    /// encoded with the sign bit set.
    static func isOnCurve(y: Element, xNegative: Bool) -> Bool {
        let one: Element = [1, 0, 0, 0]
        // d = -121665 / 121666
        let d = mul(sub([0, 0, 0, 0], [121_665, 0, 0, 0]), invert([121_666, 0, 0, 0]))
        let y2 = mul(y, y)
        let denominator = add(mul(d, y2), one)
        guard denominator != [0, 0, 0, 0] else { return false }
        let x2 = mul(sub(y2, one), invert(denominator))
        if x2 == [0, 0, 0, 0] { return !xNegative }
        // (p - 1) / 2
        let half = shiftRight(subRaw(p, one))
        return pow(x2, half) == one
    }

    static func shiftRight(_ a: Element) -> Element {
        var out = a
        for i in 0..<4 {
            let carry: UInt64 = i < 3 ? a[i + 1] << 63 : 0
            out[i] = a[i] >> 1 | carry
        }
        return out
    }
}
