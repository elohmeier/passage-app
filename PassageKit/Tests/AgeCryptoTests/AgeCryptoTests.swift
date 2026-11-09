import CryptoKit
import Foundation
import Testing

@testable import AgeCrypto

@Suite struct RoundTripTests {
    let message = Data("correct horse battery staple\nusername: alice\n".utf8)

    @Test(arguments: [0, 1, 65535, 65536, 65537, 3 * 65536])
    func x25519(size: Int) throws {
        let id = X25519Identity()
        let plaintext = Primitives.randomBytes(size)
        let ct = try Age.encrypt(plaintext, to: [id.recipient])
        #expect(try Age.decrypt(ct, identities: [id]) == plaintext)
    }

    @Test func armored() throws {
        let id = X25519Identity()
        let ct = try Age.encrypt(message, to: [id.recipient], armor: true)
        #expect(String(decoding: ct, as: UTF8.self).hasPrefix("-----BEGIN AGE ENCRYPTED FILE-----\n"))
        #expect(try Age.decrypt(ct, identities: [id]) == message)
    }

    @Test func hybrid() throws {
        let id = try HybridIdentity()
        let ct = try Age.encrypt(message, to: [id.recipient])
        #expect(try Age.decrypt(ct, identities: [id]) == message)
        #expect(try HybridIdentity(id.encoded).recipient.encoded == id.recipient.encoded)
    }

    @Test(arguments: [false, true])
    func tag(postQuantum: Bool) throws {
        let id = TagIdentity(key: try SoftwareTagKey(postQuantum: postQuantum))
        let recipient = postQuantum ? id.postQuantumRecipient! : id.classicRecipient
        let parsed = try TagRecipient(recipient.encoded)
        #expect(parsed.encoded == recipient.encoded)

        let ct = try Age.encrypt(message, to: [parsed])
        #expect(try Age.header(of: ct).stanzas[0].type == (postQuantum ? "mlkem768p256tag" : "p256tag"))
        #expect(try Age.decrypt(ct, identities: [id]) == message)
    }

    @Test(arguments: ["age1se", "age1yubikey"])
    func pivP256(hrp: String) throws {
        let key = try SoftwareTagKey(postQuantum: false)
        let recipient = try TagRecipient(Bech32.encode(hrp: hrp, data: key.p256PublicKey.compressedRepresentation))
        #expect(recipient.kind == .pivP256(hrp: hrp))
        let ct = try Age.encrypt(message, to: [recipient])
        #expect(try Age.header(of: ct).stanzas[0].type == "piv-p256")
        #expect(try Age.decrypt(ct, identities: [TagIdentity(key: key)]) == message)
    }

    @Test func tagIdentityIgnoresOtherTags() throws {
        let mine = TagIdentity(key: try SoftwareTagKey(postQuantum: false))
        let other = TagIdentity(key: try SoftwareTagKey(postQuantum: false))
        let ct = try Age.encrypt(message, to: [other.classicRecipient])
        #expect(throws: AgeError.noIdentityMatch(stanzaTypes: ["p256tag"])) {
            try Age.decrypt(ct, identities: [mine])
        }
    }

    @Test func multipleRecipients() throws {
        let a = X25519Identity()
        let b = TagIdentity(key: try SoftwareTagKey(postQuantum: false))
        let ct = try Age.encrypt(message, to: [a.recipient, b.classicRecipient])
        #expect(try Age.decrypt(ct, identities: [a]) == message)
        #expect(try Age.decrypt(ct, identities: [b]) == message)
    }

    @Test func cannotMixPostQuantumAndClassic() throws {
        let classic = X25519Identity().recipient
        let pq = try HybridIdentity().recipient
        #expect(throws: AgeError.self) { try Age.encrypt(message, to: [classic, pq]) }
    }

    @Test func tamperedHeaderFailsMAC() throws {
        let a = X25519Identity()
        let b = X25519Identity()
        var ct = try Age.encrypt(message, to: [a.recipient, b.recipient])
        // Drop the second stanza: a's file key still unwraps, but the MAC covers both.
        let header = try Age.header(of: ct)
        let stripped = Header(stanzas: [header.stanzas[0]], mac: header.mac)
        ct = stripped.encoded() + ct.dropFirst(header.encoded().count)
        #expect(throws: AgeError.headerMAC) { try Age.decrypt(ct, identities: [a]) }
    }
}

@Suite struct ParsingTests {
    @Test func bech32RoundTrip() throws {
        let data = Primitives.randomBytes(32)
        let s = Bech32.encode(hrp: "AGE-SECRET-KEY-", data: data)
        #expect(s == s.uppercased())
        let (hrp, decoded) = try Bech32.decode(s)
        #expect(hrp == "AGE-SECRET-KEY-")
        #expect(decoded == data)
        #expect(throws: AgeError.self) { try Bech32.decode(s.prefix(10).lowercased() + s.dropFirst(10)) }
    }

    @Test func recipientsFile() throws {
        let x = X25519Identity().recipient.encoded
        let tag = TagIdentity(key: try SoftwareTagKey(postQuantum: false)).classicRecipient.encoded
        let file = """
            # desktop
            \(x)

              \(tag)
            """
        let recipients = try RecipientParser.parseFile(file)
        #expect(recipients.map(\.encoded) == [x, tag])
    }

    @Test func pluginRecipientsAreRejected() {
        #expect(throws: AgeError.invalidEncoding("Recipients of the age plugin type fido2hmac are not supported")) {
            try RecipientParser.parse(Bech32.encode(hrp: "age1fido2hmac", data: Data(count: 10)))
        }
    }

    @Test func identityFile() throws {
        let a = X25519Identity()
        let b = try HybridIdentity()
        let ids = try IdentityParser.parseFile("# created: today\n# public key: …\n\(a.encoded)\n\(b.encoded)\n")
        #expect(ids.count == 2)
    }

    /// RFC 7914 §12, the p = 1 vector.
    @Test func scryptKDF() {
        let out = Scrypt.derive(
            passphrase: Data("pleaseletmein".utf8), salt: Data("SodiumChloride".utf8), logN: 14, keyLength: 64)
        #expect(out == Data(hex: """
            7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
            d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887
            """))
    }
}

@Suite struct TagAddressingTests {
    @Test(arguments: [false, true])
    func detectsStanzasForThisKeyWithoutThePrivateKey(postQuantum: Bool) throws {
        let mine = TagIdentity(key: try SoftwareTagKey(postQuantum: true))
        let other = X25519Identity()
        let recipient = postQuantum ? mine.postQuantumRecipient! : mine.classicRecipient

        let forMe = try Age.header(of: Age.encrypt(Data("x".utf8), to: [recipient]))
        // Either form of the recipient recognizes both stanza types.
        #expect(mine.classicRecipient.canDecrypt(forMe))
        #expect(mine.postQuantumRecipient!.canDecrypt(forMe))

        let notForMe = try Age.header(of: Age.encrypt(Data("x".utf8), to: [other.recipient]))
        #expect(!mine.classicRecipient.canDecrypt(notForMe))
        let otherTag = TagIdentity(key: try SoftwareTagKey(postQuantum: postQuantum))
        let forSomeoneElse = try Age.header(of: Age.encrypt(Data("x".utf8), to: [postQuantum ? otherTag.postQuantumRecipient! : otherTag.classicRecipient]))
        #expect(!mine.classicRecipient.canDecrypt(forSomeoneElse))
    }

    @Test func pivP256() throws {
        let key = try SoftwareTagKey(postQuantum: false)
        let se = try TagRecipient(Bech32.encode(hrp: "age1se", data: key.p256PublicKey.compressedRepresentation))
        let header = try Age.header(of: Age.encrypt(Data("x".utf8), to: [se]))
        #expect(TagIdentity(key: key).classicRecipient.canDecrypt(header))
    }
}

@Suite struct SSHKeyValidationTests {
    func wire(_ fields: [Data]) -> Data {
        fields.reduce(into: Data()) { out, f in
            withUnsafeBytes(of: UInt32(f.count).bigEndian) { out.append(contentsOf: $0) }
            out.append(f)
        }
    }

    func ed25519Line(_ key: Data) -> String {
        "ssh-ed25519 " + wire([Data("ssh-ed25519".utf8), key]).base64EncodedString()
    }

    @Test func ed25519PointsMustBeOnTheCurve() throws {
        for _ in 0..<50 {
            let key = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
            #expect(throws: Never.self) { try SSHEd25519Recipient(ed25519Line(key)) }
        }
        // About half of all y values have no matching x.
        var rejected = 0
        for _ in 0..<200 {
            var bytes = (0..<32).map { _ in UInt8.random(in: 0...255) }
            bytes[31] &= 0x7F
            if (try? SSHEd25519Recipient(ed25519Line(Data(bytes)))) == nil { rejected += 1 }
        }
        #expect((50...150).contains(rejected))
    }

    @Test func rsaExponentMustBeOddAndAtLeastThree() {
        let modulus = Data([0x00, 0xC0] + (0..<255).map { _ in UInt8.random(in: 0...255) } + [0x01])
        func line(_ e: [UInt8]) -> String {
            "ssh-rsa " + wire([Data("ssh-rsa".utf8), Data(e), modulus]).base64EncodedString()
        }
        #expect(throws: AgeError.self) { try SSHRSARecipient(line([0x01])) }
        #expect(throws: AgeError.self) { try SSHRSARecipient(line([0x01, 0x00, 0x00])) }
        #expect(throws: Never.self) { try SSHRSARecipient(line([0x01, 0x00, 0x01])) }
    }
}
