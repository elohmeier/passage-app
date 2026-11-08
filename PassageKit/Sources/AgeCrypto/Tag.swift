import CryptoKit
import Foundation

// Recipient types for hardware keys:
//
//   - p256tag / mlkem768p256tag: the native tagged types from https://c2sp.org/age#the-tagged-recipient-types,
//     encoded as `age1tag1…` / `age1tagpq1…`.
//   - piv-p256: the stanza used by age-plugin-yubikey (`age1yubikey1…`) and age-plugin-se (`age1se1…`)
//     recipients. Implemented natively, so we can encrypt to those without running a plugin.

private let p256tagLabel = "age-encryption.org/p256tag"
private let mlkem768p256tagLabel = "age-encryption.org/mlkem768p256tag"
private let compressedPointSize = 33
private let uncompressedPointSize = 65
private let mlkemPublicKeySize = 1184
private let mlkemCiphertextSize = 1088

/// A P-256 (and optionally ML-KEM-768) private key that can do the key agreement for tagged
/// stanzas. Implemented in software, by the Secure Enclave, or by a YubiKey.
public protocol TagPrivateKey: Sendable {
    var p256PublicKey: P256.KeyAgreement.PublicKey { get }
    /// Nil if this key has no post-quantum half.
    var mlkemPublicKey: MLKEM768.PublicKey? { get }
    /// The x-coordinate of the ECDH shared point. May prompt for user presence.
    func p256SharedSecret(with share: P256.KeyAgreement.PublicKey) throws(AgeError) -> Data
    /// ML-KEM-768 decapsulation. May prompt for user presence.
    func mlkemDecapsulate(_ ciphertext: Data) throws(AgeError) -> Data
}

public struct TagRecipient: AgeRecipient {
    public enum Kind: Sendable, Equatable {
        case p256tag
        case mlkem768p256tag
        /// Legacy plugin recipient with the given HRP (`age1se`, `age1yubikey`).
        case pivP256(hrp: String)
    }

    public let kind: Kind
    public let p256PublicKey: P256.KeyAgreement.PublicKey
    public let mlkemPublicKey: MLKEM768.PublicKey?

    public init(kind: Kind, p256PublicKey: P256.KeyAgreement.PublicKey, mlkemPublicKey: MLKEM768.PublicKey? = nil) {
        precondition((kind == .mlkem768p256tag) == (mlkemPublicKey != nil))
        self.kind = kind
        self.p256PublicKey = p256PublicKey
        self.mlkemPublicKey = mlkemPublicKey
    }

    public init(_ string: String) throws(AgeError) {
        let (hrp, data) = try Bech32.decode(string)
        switch hrp {
        case "age1tag", "age1se", "age1yubikey":
            guard data.count == compressedPointSize,
                let key = try? P256.KeyAgreement.PublicKey(compressedRepresentation: data)
            else { throw .invalidEncoding("malformed recipient: invalid P-256 public key") }
            kind = hrp == "age1tag" ? .p256tag : .pivP256(hrp: hrp)
            p256PublicKey = key
            mlkemPublicKey = nil
        case "age1tagpq":
            guard data.count == mlkemPublicKeySize + uncompressedPointSize,
                let mlkem = try? MLKEM768.PublicKey(rawRepresentation: data.prefix(mlkemPublicKeySize)),
                let p256 = try? P256.KeyAgreement.PublicKey(x963Representation: data.suffix(uncompressedPointSize))
            else { throw .invalidEncoding("malformed recipient: invalid tagpq public key") }
            kind = .mlkem768p256tag
            p256PublicKey = p256
            mlkemPublicKey = mlkem
        default:
            throw .invalidEncoding("malformed recipient: invalid type \(hrp)")
        }
    }

    public var encoded: String {
        switch kind {
        case .p256tag: Bech32.encode(hrp: "age1tag", data: p256PublicKey.compressedRepresentation)
        case .mlkem768p256tag:
            Bech32.encode(hrp: "age1tagpq", data: mlkemPublicKey!.rawRepresentation + p256PublicKey.x963Representation)
        case .pivP256(let hrp): Bech32.encode(hrp: hrp, data: p256PublicKey.compressedRepresentation)
        }
    }

    public var labels: Set<String> { kind == .mlkem768p256tag ? ["postquantum"] : [] }

    public func wrap(fileKey: Data) throws(AgeError) -> [Stanza] {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ssT: Data
        do {
            ssT = try ephemeral.sharedSecretFromKeyAgreement(with: p256PublicKey).withUnsafeBytes { Data($0) }
        } catch {
            throw .invalidEncoding("invalid P-256 recipient")
        }

        switch kind {
        case .pivP256:
            let share = ephemeral.publicKey.compressedRepresentation
            let key = Primitives.hkdf(ikm: ssT, salt: share + p256PublicKey.compressedRepresentation, info: "piv-p256")
            return [Stanza(
                type: "piv-p256", args: [Base64.encode(pivTag(p256PublicKey)), Base64.encode(share)],
                body: try Primitives.aeadEncrypt(key: key, plaintext: fileKey))]

        case .p256tag:
            let enc = ephemeral.publicKey.x963Representation
            let ss = HPKEBase.dhkemP256SharedSecret(dh: ssT, enc: enc, recipient: p256PublicKey)
            let context = HPKEBase.keySchedule(kem: .dhkemP256, sharedSecret: ss, info: p256tagLabel)
            return [Stanza(
                type: "p256tag", args: [Base64.encode(hpkeTag(enc: enc, recipient: p256PublicKey, hybrid: false)), Base64.encode(enc)],
                body: try context.seal(fileKey))]

        case .mlkem768p256tag:
            let pq: KEM.EncapsulationResult
            do {
                pq = try mlkemPublicKey!.encapsulate()
            } catch {
                throw .invalidEncoding("ML-KEM encapsulation failed: \(error)")
            }
            let encT = ephemeral.publicKey.x963Representation
            let ss = HPKEBase.mlkem768P256SharedSecret(
                ssPQ: pq.sharedSecret.data, ssT: ssT, encT: encT, recipient: p256PublicKey)
            let enc = pq.encapsulated + encT
            let context = HPKEBase.keySchedule(kem: .mlkem768P256, sharedSecret: ss, info: mlkem768p256tagLabel)
            return [Stanza(
                type: "mlkem768p256tag", args: [Base64.encode(hpkeTag(enc: enc, recipient: p256PublicKey, hybrid: true)), Base64.encode(enc)],
                body: try context.seal(fileKey))]
        }
    }
}

/// An identity backed by a `TagPrivateKey`. Unwraps p256tag, mlkem768p256tag (if the key has an
/// ML-KEM half) and piv-p256 stanzas. Tags are checked before touching the key, so hardware
/// keys only prompt for stanzas that are actually addressed to them.
public struct TagIdentity: AgeIdentity {
    public let key: any TagPrivateKey

    public init(key: any TagPrivateKey) {
        self.key = key
    }

    /// The `age1tag1…` recipient for this key.
    public var classicRecipient: TagRecipient { TagRecipient(kind: .p256tag, p256PublicKey: key.p256PublicKey) }

    /// The `age1tagpq1…` recipient, if the key has a post-quantum half.
    public var postQuantumRecipient: TagRecipient? {
        key.mlkemPublicKey.map { TagRecipient(kind: .mlkem768p256tag, p256PublicKey: key.p256PublicKey, mlkemPublicKey: $0) }
    }

    public func unwrap(stanzas: [Stanza]) throws(AgeError) -> Data {
        try unwrapFirst(stanzas, unwrap)
    }

    private func unwrap(_ stanza: Stanza) throws(AgeError) -> Data {
        let hybrid: Bool
        switch stanza.type {
        case "p256tag": hybrid = false
        case "mlkem768p256tag":
            guard key.mlkemPublicKey != nil else { throw .incorrectIdentity }
            hybrid = true
        case "piv-p256": return try unwrapPIV(stanza)
        default: throw .incorrectIdentity
        }

        guard stanza.args.count == 2, let tag = Base64.decode(stanza.args[0]), tag.count == 4,
            let enc = Base64.decode(stanza.args[1]),
            enc.count == (hybrid ? mlkemCiphertextSize + uncompressedPointSize : uncompressedPointSize)
        else { throw .header("invalid \(stanza.type) recipient block") }
        guard stanza.body.count == Primitives.fileKeySize + Primitives.tagSize else {
            throw .header("encrypted file key has unexpected length")
        }
        guard Primitives.equal(tag, hpkeTag(enc: enc, recipient: key.p256PublicKey, hybrid: hybrid)) else {
            throw .incorrectIdentity
        }

        let encT = enc.suffix(uncompressedPointSize)
        guard let share = try? P256.KeyAgreement.PublicKey(x963Representation: encT) else {
            throw .header("invalid \(stanza.type) share")
        }
        let ssT = try key.p256SharedSecret(with: share)
        let context: HPKEBase.Context
        if hybrid {
            let ssPQ = try key.mlkemDecapsulate(Data(enc.prefix(mlkemCiphertextSize)))
            let ss = HPKEBase.mlkem768P256SharedSecret(ssPQ: ssPQ, ssT: ssT, encT: Data(encT), recipient: key.p256PublicKey)
            context = HPKEBase.keySchedule(kem: .mlkem768P256, sharedSecret: ss, info: mlkem768p256tagLabel)
        } else {
            let ss = HPKEBase.dhkemP256SharedSecret(dh: ssT, enc: enc, recipient: key.p256PublicKey)
            context = HPKEBase.keySchedule(kem: .dhkemP256, sharedSecret: ss, info: p256tagLabel)
        }
        return try context.open(stanza.body)
    }

    private func unwrapPIV(_ stanza: Stanza) throws(AgeError) -> Data {
        guard stanza.args.count == 2, let tag = Base64.decode(stanza.args[0]), tag.count == 4,
            let share = Base64.decode(stanza.args[1]), share.count == compressedPointSize
        else { throw .header("invalid piv-p256 recipient block") }
        guard stanza.body.count == Primitives.fileKeySize + Primitives.tagSize else {
            throw .header("encrypted file key has unexpected length")
        }
        guard Primitives.equal(tag, pivTag(key.p256PublicKey)) else { throw .incorrectIdentity }
        guard let sharePoint = try? P256.KeyAgreement.PublicKey(compressedRepresentation: share) else {
            throw .header("invalid piv-p256 share")
        }
        let ss = try key.p256SharedSecret(with: sharePoint)
        let wrapKey = Primitives.hkdf(ikm: ss, salt: share + key.p256PublicKey.compressedRepresentation, info: "piv-p256")
        return try Primitives.aeadDecrypt(key: wrapKey, size: Primitives.fileKeySize, ciphertext: stanza.body)
    }
}

/// A software P-256 (+ ML-KEM-768) key, mostly for tests. Real devices use the Secure Enclave.
public struct SoftwareTagKey: TagPrivateKey {
    let p256: P256.KeyAgreement.PrivateKey
    let mlkem: MLKEM768.PrivateKey?

    public init(postQuantum: Bool) throws {
        p256 = P256.KeyAgreement.PrivateKey()
        mlkem = postQuantum ? try MLKEM768.PrivateKey.generate() : nil
    }

    /// Restores a key from `p256RawRepresentation` and (optionally) `mlkemSeed`.
    public init(p256RawRepresentation: Data, mlkemSeed: Data?) throws {
        p256 = try P256.KeyAgreement.PrivateKey(rawRepresentation: p256RawRepresentation)
        mlkem = try mlkemSeed.map { try MLKEM768.PrivateKey(seedRepresentation: $0, publicKey: nil) }
    }

    public var p256RawRepresentation: Data { p256.rawRepresentation }
    public var mlkemSeed: Data? { mlkem?.seedRepresentation }

    public var p256PublicKey: P256.KeyAgreement.PublicKey { p256.publicKey }
    public var mlkemPublicKey: MLKEM768.PublicKey? { mlkem?.publicKey }

    public func p256SharedSecret(with share: P256.KeyAgreement.PublicKey) throws(AgeError) -> Data {
        do {
            return try p256.sharedSecretFromKeyAgreement(with: share).withUnsafeBytes { Data($0) }
        } catch {
            throw .header("ECDH failed")
        }
    }

    public func mlkemDecapsulate(_ ciphertext: Data) throws(AgeError) -> Data {
        guard let mlkem else { throw .incorrectIdentity }
        do {
            return try mlkem.decapsulate(ciphertext).data
        } catch {
            throw .header("ML-KEM decapsulation failed")
        }
    }
}

/// `SHA-256(compressed recipient)[:4]`, as used by piv-p256.
private func pivTag(_ key: P256.KeyAgreement.PublicKey) -> Data {
    Data(SHA256.hash(data: key.compressedRepresentation).prefix(4))
}

/// `HKDF-Extract(ikm = enc || SHA-256(recipient)[:4], salt = label)[:4]`. The recipient is the
/// compressed point for p256tag and the uncompressed point for mlkem768p256tag.
private func hpkeTag(enc: Data, recipient: P256.KeyAgreement.PublicKey, hybrid: Bool) -> Data {
    let r = hybrid ? recipient.x963Representation : recipient.compressedRepresentation
    let label = hybrid ? mlkem768p256tagLabel : p256tagLabel
    let prk = HKDF<SHA256>.extract(
        inputKeyMaterial: SymmetricKey(data: enc + SHA256.hash(data: r).prefix(4)), salt: Data(label.utf8))
    return Data(prk).prefix(4)
}

/// The parts of HPKE (RFC 9180) base mode we need for single-shot sealing with
/// HKDF-SHA256 and ChaCha20-Poly1305. Implemented by hand because the private key may live in
/// the Secure Enclave or on a YubiKey, and CryptoKit has no MLKEM768-P256 KEM.
enum HPKEBase {
    enum KEMID: UInt16 {
        case dhkemP256 = 0x0010
        case mlkem768P256 = 0x0050
    }

    static func dhkemP256SharedSecret(dh: Data, enc: Data, recipient: P256.KeyAgreement.PublicKey) -> Data {
        let suite = Data("KEM".utf8) + bigEndian(KEMID.dhkemP256.rawValue)
        let prk = labeledExtract(suite: suite, salt: Data(), label: "eae_prk", ikm: dh)
        return labeledExpand(
            suite: suite, prk: prk, label: "shared_secret", info: enc + recipient.x963Representation, length: 32)
    }

    /// The MLKEM768-P256 combiner from draft-ietf-hpke-pq.
    static func mlkem768P256SharedSecret(ssPQ: Data, ssT: Data, encT: Data, recipient: P256.KeyAgreement.PublicKey) -> Data {
        var h = SHA3_256()
        h.update(data: ssPQ)
        h.update(data: ssT)
        h.update(data: encT)
        h.update(data: recipient.x963Representation)
        h.update(data: Data("MLKEM768-P256".utf8))
        return Data(h.finalize())
    }

    /// A mode_base context for a single message (sequence number 0).
    struct Context {
        let key: SymmetricKey
        let nonce: ChaChaPoly.Nonce

        func seal(_ plaintext: Data) throws(AgeError) -> Data {
            guard let box = try? ChaChaPoly.seal(plaintext, using: key, nonce: nonce) else {
                throw .invalidEncoding("HPKE seal failed")
            }
            return box.ciphertext + box.tag
        }

        /// Opens a wrapped file key; the caller has already checked the length.
        func open(_ ciphertext: Data) throws(AgeError) -> Data {
            guard let box = try? ChaChaPoly.SealedBox(
                nonce: nonce, ciphertext: ciphertext.dropLast(Primitives.tagSize), tag: ciphertext.suffix(Primitives.tagSize)),
                let plaintext = try? ChaChaPoly.open(box, using: key)
            else { throw .incorrectIdentity }
            return plaintext
        }
    }

    static func keySchedule(kem: KEMID, sharedSecret: Data, info: String) -> Context {
        // KDF 0x0001 = HKDF-SHA256, AEAD 0x0003 = ChaCha20Poly1305.
        let suite = Data("HPKE".utf8) + bigEndian(kem.rawValue) + bigEndian(0x0001) + bigEndian(0x0003)
        let pskIDHash = labeledExtract(suite: suite, salt: Data(), label: "psk_id_hash", ikm: Data())
        let infoHash = labeledExtract(suite: suite, salt: Data(), label: "info_hash", ikm: Data(info.utf8))
        let context = Data([0x00]) + pskIDHash + infoHash
        let secret = labeledExtract(suite: suite, salt: sharedSecret, label: "secret", ikm: Data())
        return Context(
            key: SymmetricKey(data: labeledExpand(suite: suite, prk: secret, label: "key", info: context, length: 32)),
            nonce: try! ChaChaPoly.Nonce(data: labeledExpand(suite: suite, prk: secret, label: "base_nonce", info: context, length: 12)))
    }

    static func labeledExtract(suite: Data, salt: Data, label: String, ikm: Data) -> Data {
        let labeled = Data("HPKE-v1".utf8) + suite + Data(label.utf8) + ikm
        return Data(HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeled), salt: salt))
    }

    static func labeledExpand(suite: Data, prk: Data, label: String, info: Data, length: Int) -> Data {
        let labeled = bigEndian(UInt16(length)) + Data("HPKE-v1".utf8) + suite + Data(label.utf8) + info
        return HKDF<SHA256>.expand(pseudoRandomKey: SymmetricKey(data: prk), info: labeled, outputByteCount: length).data
    }

    static func bigEndian(_ v: UInt16) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xFF)]) }
}

extension TagRecipient {
    /// True if `stanza` is addressed to this key, judged from public data only (the stanza's
    /// tag). Works for p256tag, mlkem768p256tag and piv-p256, whichever form of the recipient
    /// this is, so it needs no user presence and never touches the private key.
    public func isAddressed(by stanza: Stanza) -> Bool {
        guard stanza.args.count == 2, let tag = Base64.decode(stanza.args[0]), tag.count == 4,
            let enc = Base64.decode(stanza.args[1])
        else { return false }
        switch stanza.type {
        case "p256tag": return Primitives.equal(tag, hpkeTag(enc: enc, recipient: p256PublicKey, hybrid: false))
        case "mlkem768p256tag": return Primitives.equal(tag, hpkeTag(enc: enc, recipient: p256PublicKey, hybrid: true))
        case "piv-p256": return Primitives.equal(tag, pivTag(p256PublicKey))
        default: return false
        }
    }

    /// True if any stanza in `header` is addressed to this key.
    public func canDecrypt(_ header: Header) -> Bool {
        header.stanzas.contains(where: isAddressed)
    }
}

extension TagRecipient {
    /// The ephemeral P-256 share of a stanza addressed to this key (see `isAddressed`), i.e.
    /// the input for the key agreement a hardware token must perform.
    public func share(in stanza: Stanza) -> P256.KeyAgreement.PublicKey? {
        guard isAddressed(by: stanza), let enc = Base64.decode(stanza.args[1]) else { return nil }
        switch stanza.type {
        case "p256tag": return try? P256.KeyAgreement.PublicKey(x963Representation: enc)
        case "piv-p256": return try? P256.KeyAgreement.PublicKey(compressedRepresentation: enc)
        default: return nil  // mlkem768p256tag needs ML-KEM, which PIV tokens don't have
        }
    }
}

/// A tag key whose ECDH results were computed elsewhere (e.g. on a YubiKey over NFC) before
/// decryption, so the synchronous decrypt path never waits on hardware I/O.
public struct PrecomputedTagKey: TagPrivateKey {
    public let p256PublicKey: P256.KeyAgreement.PublicKey
    /// Shared secrets by the share's x963 representation.
    let secrets: [Data: Data]

    /// `secrets` maps each share's x963 representation to the ECDH result for it.
    public init(publicKey: P256.KeyAgreement.PublicKey, secrets: [Data: Data]) {
        p256PublicKey = publicKey
        self.secrets = secrets
    }

    public var mlkemPublicKey: MLKEM768.PublicKey? { nil }

    public func p256SharedSecret(with share: P256.KeyAgreement.PublicKey) throws(AgeError) -> Data {
        guard let secret = secrets[share.x963Representation] else { throw .identityUnavailable("no key agreement for this stanza") }
        return secret
    }

    public func mlkemDecapsulate(_ ciphertext: Data) throws(AgeError) -> Data {
        throw .incorrectIdentity
    }
}
