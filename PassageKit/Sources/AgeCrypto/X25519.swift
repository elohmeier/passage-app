import CryptoKit
import Foundation

private let x25519Label = "age-encryption.org/v1/X25519"

/// The classic age recipient, `age1…`.
public struct X25519Recipient: AgeRecipient {
    public let publicKey: Curve25519.KeyAgreement.PublicKey

    public init(publicKey: Curve25519.KeyAgreement.PublicKey) {
        self.publicKey = publicKey
    }

    public init(_ string: String) throws(AgeError) {
        let (hrp, data) = try Bech32.decode(string)
        guard hrp == "age" else { throw .invalidEncoding("malformed recipient: invalid type \(hrp)") }
        guard data.count == 32, let key = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: data) else {
            throw .invalidEncoding("malformed recipient: invalid X25519 public key")
        }
        publicKey = key
    }

    public var encoded: String { Bech32.encode(hrp: "age", data: publicKey.rawRepresentation) }

    public func wrap(fileKey: Data) throws(AgeError) -> [Stanza] {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let share = ephemeral.publicKey.rawRepresentation
        guard let shared = try? ephemeral.sharedSecretFromKeyAgreement(with: publicKey) else {
            throw .invalidEncoding("invalid X25519 recipient")
        }
        let key = Primitives.hkdf(
            ikm: shared.withUnsafeBytes { Data($0) }, salt: share + publicKey.rawRepresentation, info: x25519Label)
        return [Stanza(type: "X25519", args: [Base64.encode(share)], body: try Primitives.aeadEncrypt(key: key, plaintext: fileKey))]
    }
}

/// `AGE-SECRET-KEY-1…`
public struct X25519Identity: AgeIdentity {
    let privateKey: Curve25519.KeyAgreement.PrivateKey

    public init() {
        privateKey = Curve25519.KeyAgreement.PrivateKey()
    }

    public init(_ string: String) throws(AgeError) {
        let (hrp, data) = try Bech32.decode(string)
        guard hrp == "AGE-SECRET-KEY-" else { throw .invalidEncoding("malformed secret key: unknown type \(hrp)") }
        guard data.count == 32, let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) else {
            throw .invalidEncoding("malformed secret key")
        }
        privateKey = key
    }

    public var encoded: String { Bech32.encode(hrp: "AGE-SECRET-KEY-", data: privateKey.rawRepresentation) }

    public var recipient: X25519Recipient { X25519Recipient(publicKey: privateKey.publicKey) }

    public func unwrap(stanzas: [Stanza]) throws(AgeError) -> Data {
        try unwrapFirst(stanzas, unwrap)
    }

    private func unwrap(_ stanza: Stanza) throws(AgeError) -> Data {
        guard stanza.type == "X25519" else { throw .incorrectIdentity }
        guard stanza.args.count == 1 else { throw .header("invalid X25519 recipient block") }
        guard let share = Base64.decode(stanza.args[0]), share.count == 32,
            let sharePoint = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: share)
        else { throw .header("invalid X25519 recipient block") }

        guard let secret = try? privateKey.sharedSecretFromKeyAgreement(with: sharePoint) else {
            throw .header("invalid X25519 recipient")
        }
        let shared = secret.withUnsafeBytes { Data($0) }
        guard shared.contains(where: { $0 != 0 }) else { throw .header("X25519 low order point") }

        let key = Primitives.hkdf(ikm: shared, salt: share + privateKey.publicKey.rawRepresentation, info: x25519Label)
        return try Primitives.aeadDecrypt(key: key, size: Primitives.fileKeySize, ciphertext: stanza.body)
    }
}
