import CryptoKit
import Foundation

enum Primitives {
    static let fileKeySize = 16
    static let tagSize = 16

    static func hkdf(ikm: some DataProtocol, salt: some DataProtocol, info: String, count: Int = 32) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(ikm)), salt: Data(salt), info: Data(info.utf8),
            outputByteCount: count)
    }

    /// ChaCha20-Poly1305 with an all-zero nonce, as used to wrap file keys. Every wrapping key
    /// is used exactly once.
    static func aeadEncrypt(key: SymmetricKey, plaintext: Data) throws(AgeError) -> Data {
        do {
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: ChaChaPoly.Nonce(data: Data(count: 12)))
            return box.ciphertext + box.tag
        } catch {
            throw .header("internal error: \(error)")
        }
    }

    /// Opens a wrapped file key. A wrong length is a malformed stanza; a failed tag means the
    /// stanza isn't for us.
    static func aeadDecrypt(key: SymmetricKey, size: Int, ciphertext: Data) throws(AgeError) -> Data {
        guard ciphertext.count == size + tagSize else { throw .header("encrypted file key has unexpected length") }
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: Data(count: 12)),
                ciphertext: ciphertext.prefix(size), tag: ciphertext.suffix(tagSize))
            return try ChaChaPoly.open(box, using: key)
        } catch {
            throw .incorrectIdentity
        }
    }

    static func headerMAC(fileKey: Data, header: Header) -> Data {
        let key = hkdf(ikm: fileKey, salt: Data(), info: "header")
        return Data(HMAC<SHA256>.authenticationCode(for: header.encodedWithoutMAC(), using: key))
    }

    static func randomBytes(_ count: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }

    /// Constant-time comparison.
    static func equal(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}

extension SymmetricKey {
    var data: Data { withUnsafeBytes { Data($0) } }
}
