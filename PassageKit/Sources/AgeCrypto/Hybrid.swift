import CryptoKit
import Foundation

private let pqLabel = Data("age-encryption.org/mlkem768x25519".utf8)
private let suite = HPKE.Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .chaChaPoly)
private let encapsulatedKeySize = 1120

/// The post-quantum hybrid recipient (MLKEM768-X25519, i.e. X-Wing), `age1pq1…`.
public struct HybridRecipient: AgeRecipient {
    public let publicKey: XWingMLKEM768X25519.PublicKey

    public init(publicKey: XWingMLKEM768X25519.PublicKey) {
        self.publicKey = publicKey
    }

    public init(_ string: String) throws(AgeError) {
        let (hrp, data) = try Bech32.decode(string)
        guard hrp == "age1pq" else { throw .invalidEncoding("malformed recipient: invalid type \(hrp)") }
        guard let key = try? XWingMLKEM768X25519.PublicKey(rawRepresentation: data) else {
            throw .invalidEncoding("malformed recipient: invalid MLKEM768-X25519 public key")
        }
        publicKey = key
    }

    public var encoded: String { Bech32.encode(hrp: "age1pq", data: publicKey.rawRepresentation) }

    public var labels: Set<String> { ["postquantum"] }

    public func wrap(fileKey: Data) throws(AgeError) -> [Stanza] {
        do {
            var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: suite, info: pqLabel)
            let body = try sender.seal(fileKey)
            return [Stanza(type: "mlkem768x25519", args: [Base64.encode(sender.encapsulatedKey)], body: body)]
        } catch {
            throw .invalidEncoding("failed to wrap file key: \(error)")
        }
    }
}

/// `AGE-SECRET-KEY-PQ-1…`: a 32-byte seed.
public struct HybridIdentity: AgeIdentity {
    let privateKey: XWingMLKEM768X25519.PrivateKey

    public init() throws(AgeError) {
        do {
            privateKey = try XWingMLKEM768X25519.PrivateKey.generate()
        } catch {
            throw .identityUnavailable("failed to generate post-quantum identity: \(error)")
        }
    }

    public init(_ string: String) throws(AgeError) {
        let (hrp, data) = try Bech32.decode(string)
        guard hrp == "AGE-SECRET-KEY-PQ-" else { throw .invalidEncoding("malformed secret key: unknown type \(hrp)") }
        guard data.count == 32, let key = try? XWingMLKEM768X25519.PrivateKey(seedRepresentation: data, publicKey: nil) else {
            throw .invalidEncoding("malformed secret key")
        }
        privateKey = key
    }

    public var encoded: String { Bech32.encode(hrp: "AGE-SECRET-KEY-PQ-", data: privateKey.seedRepresentation) }

    public var recipient: HybridRecipient { HybridRecipient(publicKey: privateKey.publicKey) }

    public func unwrap(stanzas: [Stanza]) throws(AgeError) -> Data {
        try unwrapFirst(stanzas, unwrap)
    }

    private func unwrap(_ stanza: Stanza) throws(AgeError) -> Data {
        guard stanza.type == "mlkem768x25519" else { throw .incorrectIdentity }
        guard stanza.args.count == 1 else { throw .header("invalid mlkem768x25519 recipient block") }
        guard let enc = Base64.decode(stanza.args[0]), enc.count == encapsulatedKeySize else {
            throw .header("invalid mlkem768x25519 recipient block")
        }
        // Check the length before decrypting, to avoid partitioning oracles.
        guard stanza.body.count == Primitives.fileKeySize + Primitives.tagSize else {
            throw .header("encrypted file key has unexpected length")
        }
        let recipient: HPKE.Recipient
        do {
            recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: suite, info: pqLabel, encapsulatedKey: enc)
        } catch {
            throw .header("invalid mlkem768x25519 recipient: \(error)")
        }
        var r = recipient
        guard let fileKey = try? r.open(stanza.body) else { throw .incorrectIdentity }
        return fileKey
    }
}
