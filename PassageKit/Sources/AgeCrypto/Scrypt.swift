import CommonCrypto
import Foundation

private let scryptLabel = Data("age-encryption.org/v1/scrypt".utf8)
private let saltSize = 16

/// Passphrase identity. Only used to decrypt passphrase-protected identity files, so there is
/// no matching recipient: the app never encrypts store entries to a passphrase.
public struct ScryptIdentity: AgeIdentity {
    let passphrase: Data
    /// Upper bound on log2(N). The memory needed is 2^logN KiB, so 20 = 1 GiB is about as far
    /// as an iOS app can go. age's default for new files is 18.
    public var maxWorkFactor: Int

    public init(passphrase: String, maxWorkFactor: Int = 20) {
        self.passphrase = Data(passphrase.utf8)
        self.maxWorkFactor = maxWorkFactor
    }

    public func unwrap(stanzas: [Stanza]) throws(AgeError) -> Data {
        guard let stanza = stanzas.first(where: { $0.type == "scrypt" }) else { throw .incorrectIdentity }
        guard stanzas.count == 1 else { throw .header("an scrypt recipient must be the only one") }

        guard stanza.args.count == 2, let salt = Base64.decode(stanza.args[0]), salt.count == saltSize else {
            throw .header("invalid scrypt recipient block")
        }
        let w = stanza.args[1]
        guard let first = w.utf8.first, first != UInt8(ascii: "0"), w.utf8.allSatisfy({ (48...57).contains($0) }) else {
            throw .header("scrypt work factor encoding invalid")
        }
        guard w.count <= 2, let logN = Int(w), logN <= maxWorkFactor else { throw .header("scrypt work factor too large") }

        let key = Scrypt.derive(passphrase: passphrase, salt: scryptLabel + salt, logN: logN)
        do {
            return try Primitives.aeadDecrypt(key: .init(data: key), size: Primitives.fileKeySize, ciphertext: stanza.body)
        } catch .incorrectIdentity {
            // Wrong passphrase.
            throw .incorrectIdentity
        }
    }
}

/// scrypt (RFC 7914) with r = 8, p = 1.
enum Scrypt {
    static func derive(passphrase: Data, salt: Data, logN: Int, keyLength: Int = 32) -> Data {
        let r = 8
        let n = 1 << logN
        let blockWords = 32 * r

        var b = pbkdf2(passphrase: passphrase, salt: salt, length: 128 * r)
        var x = [UInt32](repeating: 0, count: blockWords)
        b.withUnsafeBytes { raw in
            for i in 0..<blockWords { x[i] = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 4 * i, as: UInt32.self)) }
        }

        var v = [UInt32](repeating: 0, count: blockWords * n)
        var scratch = [UInt32](repeating: 0, count: blockWords)
        x.withUnsafeMutableBufferPointer { x in
            v.withUnsafeMutableBufferPointer { v in
                scratch.withUnsafeMutableBufferPointer { y in
                    for i in 0..<n {
                        v.baseAddress!.advanced(by: i * blockWords).update(from: x.baseAddress!, count: blockWords)
                        blockMix(x, y, r: r)
                    }
                    for _ in 0..<n {
                        let j = Int(x[(2 * r - 1) * 16]) & (n - 1)
                        let vj = v.baseAddress!.advanced(by: j * blockWords)
                        for k in 0..<blockWords { x[k] ^= vj[k] }
                        blockMix(x, y, r: r)
                    }
                }
            }
        }

        b.withUnsafeMutableBytes { raw in
            for i in 0..<blockWords { raw.storeBytes(of: x[i].littleEndian, toByteOffset: 4 * i, as: UInt32.self) }
        }
        return pbkdf2(passphrase: passphrase, salt: b, length: keyLength)
    }

    /// BlockMix with Salsa20/8, in place on `b` using `y` as scratch space.
    private static func blockMix(_ b: UnsafeMutableBufferPointer<UInt32>, _ y: UnsafeMutableBufferPointer<UInt32>, r: Int) {
        var t = [UInt32](repeating: 0, count: 16)
        for k in 0..<16 { t[k] = b[(2 * r - 1) * 16 + k] }
        for i in 0..<(2 * r) {
            for k in 0..<16 { t[k] ^= b[i * 16 + k] }
            salsa8(&t)
            // Even blocks go to the first half of the output, odd blocks to the second.
            let dst = (i / 2 + (i % 2) * r) * 16
            for k in 0..<16 { y[dst + k] = t[k] }
        }
        b.baseAddress!.update(from: y.baseAddress!, count: 32 * r)
    }

    private static func salsa8(_ b: inout [UInt32]) {
        var x = b
        @inline(__always) func r(_ a: UInt32, _ n: UInt32) -> UInt32 { a << n | a >> (32 - n) }
        for _ in 0..<4 {
            x[4] ^= r(x[0] &+ x[12], 7); x[8] ^= r(x[4] &+ x[0], 9)
            x[12] ^= r(x[8] &+ x[4], 13); x[0] ^= r(x[12] &+ x[8], 18)
            x[9] ^= r(x[5] &+ x[1], 7); x[13] ^= r(x[9] &+ x[5], 9)
            x[1] ^= r(x[13] &+ x[9], 13); x[5] ^= r(x[1] &+ x[13], 18)
            x[14] ^= r(x[10] &+ x[6], 7); x[2] ^= r(x[14] &+ x[10], 9)
            x[6] ^= r(x[2] &+ x[14], 13); x[10] ^= r(x[6] &+ x[2], 18)
            x[3] ^= r(x[15] &+ x[11], 7); x[7] ^= r(x[3] &+ x[15], 9)
            x[11] ^= r(x[7] &+ x[3], 13); x[15] ^= r(x[11] &+ x[7], 18)

            x[1] ^= r(x[0] &+ x[3], 7); x[2] ^= r(x[1] &+ x[0], 9)
            x[3] ^= r(x[2] &+ x[1], 13); x[0] ^= r(x[3] &+ x[2], 18)
            x[6] ^= r(x[5] &+ x[4], 7); x[7] ^= r(x[6] &+ x[5], 9)
            x[4] ^= r(x[7] &+ x[6], 13); x[5] ^= r(x[4] &+ x[7], 18)
            x[11] ^= r(x[10] &+ x[9], 7); x[8] ^= r(x[11] &+ x[10], 9)
            x[9] ^= r(x[8] &+ x[11], 13); x[10] ^= r(x[9] &+ x[8], 18)
            x[12] ^= r(x[15] &+ x[14], 7); x[13] ^= r(x[12] &+ x[15], 9)
            x[14] ^= r(x[13] &+ x[12], 13); x[15] ^= r(x[14] &+ x[13], 18)
        }
        for i in 0..<16 { b[i] = b[i] &+ x[i] }
    }

    static func pbkdf2(passphrase: Data, salt: Data, length: Int) -> Data {
        var out = Data(count: length)
        let status = out.withUnsafeMutableBytes { outPtr in
            salt.withUnsafeBytes { saltPtr in
                passphrase.withUnsafeBytes { passPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passPtr.baseAddress?.assumingMemoryBound(to: CChar.self), passphrase.count,
                        saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 1,
                        outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), length)
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed")
        return out
    }
}
