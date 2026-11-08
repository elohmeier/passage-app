import Foundation

/// Something a file key can be encrypted to.
public protocol AgeRecipient: Sendable {
    /// Wraps the 16-byte file key into one or more stanzas.
    func wrap(fileKey: Data) throws(AgeError) -> [Stanza]
    /// Labels that must match across all recipients of a file (see the age plugin spec).
    /// Post-quantum recipients carry `postquantum`, so they can't be mixed with classic ones.
    var labels: Set<String> { get }
    /// The canonical string encoding (`age1…`).
    var encoded: String { get }
}

extension AgeRecipient {
    public var labels: Set<String> { [] }
}

/// Something that can unwrap a file key.
public protocol AgeIdentity: Sendable {
    /// Returns the file key, throws `.incorrectIdentity` if no stanza is addressed to this
    /// identity, or another error if a stanza is addressed to it but malformed.
    func unwrap(stanzas: [Stanza]) throws(AgeError) -> Data
}

/// Helper for identities that look at stanzas independently.
func unwrapFirst(_ stanzas: [Stanza], _ unwrap: (Stanza) throws(AgeError) -> Data) throws(AgeError) -> Data {
    for stanza in stanzas {
        do {
            return try unwrap(stanza)
        } catch .incorrectIdentity {
            continue
        }
    }
    throw .incorrectIdentity
}

public enum Age {
    /// Encrypts `plaintext` to all `recipients`.
    public static func encrypt(_ plaintext: Data, to recipients: [any AgeRecipient], armor: Bool = false) throws(AgeError) -> Data {
        guard let first = recipients.first else { throw .noRecipients }
        let fileKey = Primitives.randomBytes(Primitives.fileKeySize)

        var stanzas: [Stanza] = []
        for r in recipients {
            guard r.labels == first.labels else {
                if r.labels.contains("postquantum") != first.labels.contains("postquantum") {
                    throw .incompatibleRecipients(
                        "Can't mix post-quantum and classic recipients, or the file would be vulnerable to quantum computers")
                }
                throw .incompatibleRecipients("Recipients \(first.encoded) and \(r.encoded) can't be mixed")
            }
            stanzas += try r.wrap(fileKey: fileKey)
        }
        var header = Header(stanzas: stanzas, mac: Data())
        header.mac = Primitives.headerMAC(fileKey: fileKey, header: header)

        let nonce = Primitives.randomBytes(PayloadStream.nonceSize)
        let out = header.encoded() + nonce
            + PayloadStream.encrypt(plaintext, key: PayloadStream.key(fileKey: fileKey, nonce: nonce))
        return armor ? Armor.encode(out) : out
    }

    /// Decrypts an age file, binary or armored, with the first identity that matches.
    public static func decrypt(_ ciphertext: Data, identities: [any AgeIdentity]) throws(AgeError) -> Data {
        var out = Data()
        try decrypt(ciphertext, identities: identities) { out.append($0) }
        return out
    }

    /// Streaming variant: `sink` receives authenticated plaintext chunks in order. If this
    /// throws a `.payload` error, the data already delivered is authentic but incomplete.
    public static func decrypt(
        _ ciphertext: Data, identities: [any AgeIdentity], sink: (Data) -> Void
    ) throws(AgeError) {
        let raw = Armor.isArmored(ciphertext) ? try Armor.decode(ciphertext) : ciphertext
        let (header, offset) = try Header.parse(raw)
        let fileKey = try unwrapFileKey(header, identities: identities)

        let payload = raw[(raw.startIndex + offset)...]
        guard payload.count >= PayloadStream.nonceSize else { throw .header("failed to read nonce") }
        let nonce = payload.prefix(PayloadStream.nonceSize)
        try PayloadStream.decrypt(
            payload.dropFirst(PayloadStream.nonceSize), key: PayloadStream.key(fileKey: fileKey, nonce: nonce),
            sink: sink)
    }

    /// Parses just the header, for inspecting which recipient types a file was encrypted to.
    public static func header(of ciphertext: Data) throws(AgeError) -> Header {
        let raw = Armor.isArmored(ciphertext) ? try Armor.decode(ciphertext) : ciphertext
        return try Header.parse(raw).header
    }

    static func unwrapFileKey(_ header: Header, identities: [any AgeIdentity]) throws(AgeError) -> Data {
        for identity in identities {
            let fileKey: Data
            do {
                fileKey = try identity.unwrap(stanzas: header.stanzas)
            } catch .incorrectIdentity {
                continue
            }
            guard Primitives.equal(Primitives.headerMAC(fileKey: fileKey, header: header), header.mac) else {
                throw .headerMAC
            }
            return fileKey
        }
        throw .noIdentityMatch(stanzaTypes: header.stanzas.map(\.type))
    }
}
