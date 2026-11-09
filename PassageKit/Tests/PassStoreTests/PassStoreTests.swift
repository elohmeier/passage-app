import CryptoKit
import AgeCrypto
import Foundation
import Testing

@testable import PassStore

@Suite struct EntryTests {
    @Test func passwordAndFields() {
        let e = Entry("hunter2\nusername: alice\nurl: https://example.com/login\nnote: see: here\njust a line\n")
        #expect(e.password == "hunter2")
        #expect(e.username == "alice")
        #expect(e.url == "https://example.com/login")
        #expect(e.fields.map(\.key) == ["username", "url", "note", nil])
        // Split at the first ": " only (passforios truncates this to "see").
        #expect(e.fields[2].value == "see: here")
        #expect(e.fields[3].value == "just a line")
        #expect(e.otp == nil)
    }

    @Test func usernameFallbacks() {
        #expect(Entry("x\nuser: u\nlogin: l").username == "l")
        #expect(Entry("x\nUser: u").username == "u")
        #expect(Entry("x").username == nil)
    }

    @Test func crlfAndEmptyLines() {
        let e = Entry("pw\r\n\r\nusername: bob\r\n")
        #expect(e.password == "pw")
        #expect(e.username == "bob")
    }

    @Test func emptyFile() {
        let e = Entry("")
        #expect(e.password == "")
        #expect(e.fields.isEmpty)
    }

    @Test func multilineValues() {
        let e = Entry("pw\nnotes: |\n  line one\n  line two\nfolded: >\n  a\n  b\nafter: x\n")
        #expect(e.fields.map(\.key) == ["notes", "folded", "after"])
        #expect(e.fields[0].value == "line one\nline two")
        #expect(e.fields[1].value == "a b")
    }

    @Test func otpauthLineIsNotAField() {
        let e = Entry("pw\notpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\nusername: alice")
        #expect(e.fields.map(\.key) == ["username"])
        #expect(e.otp?.issuer == "Example")
        #expect(e.otp?.account == "alice")
        #expect(e.otp?.period == 30)
    }

    @Test func otpOnlyEntry() {
        let e = Entry("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
        #expect(e.password == nil)
        #expect(e.otp != nil)
    }

    @Test func passforiosOTPFields() {
        let e = Entry("pw\notp_secret: GEZDGNBVGY3TQOJQ\notp_digits: 8\notp_period: 60\notp_algorithm: sha256")
        #expect(e.fields.isEmpty)
        #expect(e.otp?.digits == 8)
        #expect(e.otp?.period == 60)
        #expect(e.otp?.algorithm == .sha256)
    }

    @Test func sensitiveFields() {
        let e = Entry("pw\nPIN: 1234\nusername: a\nrecovery codes: x")
        #expect(e.fields.map(\.isSensitive) == [true, false, true])
    }
}

@Suite struct OTPTests {
    let sha1Secret = Data("12345678901234567890".utf8)

    /// RFC 4226 appendix D.
    @Test func hotp() {
        let otp = OTP(kind: .hotp(counter: 0), secret: sha1Secret)
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        #expect((0..<10).map { otp.code(counter: UInt64($0)) } == expected)
    }

    /// RFC 6238 appendix B.
    @Test(arguments: [
        (59.0, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ])
    func totp(time: Double, sha1: String, sha256: String, sha512: String) {
        let date = Date(timeIntervalSince1970: time)
        #expect(OTP(kind: .totp(period: 30), secret: sha1Secret, digits: 8).code(at: date) == sha1)
        #expect(OTP(kind: .totp(period: 30), secret: Data("12345678901234567890123456789012".utf8), algorithm: .sha256, digits: 8).code(at: date) == sha256)
        #expect(OTP(kind: .totp(period: 30), secret: Data(String(repeating: "1234567890", count: 7).prefix(64).utf8), algorithm: .sha512, digits: 8).code(at: date) == sha512)
    }

    @Test func uriParsing() throws {
        let otp = try #require(OTP(uri: "otpauth://totp/ACME%20Co:john@example.com?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=ACME%20Co&algorithm=SHA1&digits=8&period=30"))
        #expect(otp.secret == sha1Secret)
        #expect(otp.issuer == "ACME Co")
        #expect(otp.account == "john@example.com")
        #expect(otp.code(at: Date(timeIntervalSince1970: 59)) == "94287082")
        #expect(OTP(uri: "otpauth://totp/x") == nil, "secret is required")
        #expect(OTP(uri: "otpauth://hotp/x?secret=GEZDGNBV") == nil, "HOTP needs a counter")
    }

    @Test func steam() throws {
        let otp = try #require(OTP(uri: "otpauth://totp/Steam:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&encoder=steam"))
        #expect(otp.steam)
        let code = otp.code(at: Date(timeIntervalSince1970: 59))
        #expect(code.count == 5)
        #expect(code.allSatisfy { "23456789BCDFGHJKMNPQRTVWXY".contains($0) })
    }

    @Test func secondsRemaining() {
        let otp = OTP(kind: .totp(period: 30), secret: sha1Secret)
        #expect(otp.secondsRemaining(at: Date(timeIntervalSince1970: 61)) == 29)
    }
}

@Suite struct StoreTests {
    let root: URL

    init() throws {
        root = FileManager.default.temporaryDirectory.appending(path: "passstore-\(UUID().uuidString)", directoryHint: .isDirectory)
        for path in [
            "email/work/alice.age", "email/personal.age", "bank.age", "Ünïcode/thing.age",
            ".git/objects/x.age", ".extensions/foo.age", "email/notes.txt", "deep/a/b/c/leaf.age",
            "email/.hidden.age.icloud",
        ] {
            let url = root.appending(path: path)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("x".utf8).write(to: url)
        }
    }

    @Test func scan() throws {
        let s = try StoreSnapshot.scan(root: root)
        #expect(s.entries.map(\.path) == ["bank", "deep/a/b/c/leaf", "email/hidden", "email/personal", "email/work/alice", "Ünïcode/thing"])
        #expect(s.folders == ["deep", "deep/a", "deep/a/b", "deep/a/b/c", "email", "email/work", "Ünïcode"])
        let rootContents = s.contents(of: "")
        #expect(rootContents.folders == ["deep", "email", "Ünïcode"])
        #expect(rootContents.entries.map(\.path) == ["bank"])
        #expect(s.contents(of: "email").entries.map(\.name) == ["hidden", "personal"])
    }

    @Test func search() throws {
        let s = try StoreSnapshot.scan(root: root)
        #expect(s.search("ALI").map(\.path) == ["email/work/alice"])
        #expect(s.search("email work").map(\.path) == ["email/work/alice"])
        #expect(s.search("unicode").map(\.path) == ["Ünïcode/thing"])
        // Name prefix matches rank above path-only matches.
        #expect(s.search("al").map(\.path) == ["email/work/alice", "email/personal"])
        #expect(s.search("").count == 6)
    }

    @Test func nearestRecipientsFile() throws {
        let store = LocalStore(root: root)
        #expect(store.recipientsFile(for: EntryPath("email/work/alice")) == nil)
        try Data("# top\n".utf8).write(to: root.appending(path: ".age-recipients"))
        try Data("".utf8).write(to: root.appending(path: "email/.age-recipients"))
        #expect(store.recipientsFile(for: EntryPath("email/work/alice"))?.path() == root.appending(path: "email/.age-recipients").path())
        #expect(store.recipientsFile(for: EntryPath("bank"))?.path() == root.appending(path: ".age-recipients").path())
    }

    @Test func readAndRecipients() async throws {
        let id = X25519Identity()
        try Age.encrypt(Data("s3cret\n".utf8), to: [id.recipient]).write(to: root.appending(path: "bank.age"))
        try Data("# me\n\(id.recipient.encoded)\n".utf8).write(to: root.appending(path: ".age-recipients"))

        let store = LocalStore(root: root)
        let data = try await store.read(EntryPath("bank"))
        #expect(try Age.decrypt(data, identities: [id]) == Data("s3cret\n".utf8))
        #expect(try await store.recipients(for: EntryPath("bank")).map(\.encoded) == [id.recipient.encoded])
        #expect(try await store.snapshot().entries.count == 6)
        await #expect(throws: StoreError.notFound("nope")) { try await store.read(EntryPath("nope")) }
    }

    @Test func invalidRecipientsFileNamesTheFile() async throws {
        try Data("age1nonsense\n".utf8).write(to: root.appending(path: "email/.age-recipients"))
        await #expect(throws: StoreError.self) {
            try await LocalStore(root: root).recipients(for: EntryPath("email/personal"))
        }
    }
}

@Suite struct DemoStoreTests {
    @Test func createsDecryptableStore() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "demo-\(UUID().uuidString)", directoryHint: .isDirectory)
        let id = X25519Identity()
        try DemoStore.create(at: root, recipients: [id.recipient])
        let store = LocalStore(root: root)
        let snapshot = try await store.snapshot()
        #expect(snapshot.entries.count == DemoStore.entries.count)
        let mastodon = Entry(String(decoding: try Age.decrypt(await store.read(EntryPath("social/mastodon")), identities: [id]), as: UTF8.self))
        #expect(mastodon.otp != nil)
        #expect(try await store.recipients(for: EntryPath("home/wifi")).map(\.encoded) == [id.recipient.encoded])
    }
}

@Suite struct EntryDraftTests {
    @Test func roundTripKeepsFieldsAndOrder() {
        let text = "hunter2\nusername: alice\nurl: https://example.com\npin: 1234\nnotes: |\n  line one\n  line two\nloose note\notpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&issuer=Ex\n"
        let draft = EntryDraft(text)
        #expect(draft.text == text)
        #expect(Entry(draft.text) == Entry(text))
    }

    @Test func editsUsernameAndURL() {
        var draft = EntryDraft("pw\npin: 1\n")
        draft.url = "https://a.example"
        draft.username = "bob"
        #expect(draft.text == "pw\nusername: bob\nurl: https://a.example\npin: 1\n")
        draft.username = ""
        #expect(draft.text == "pw\nurl: https://a.example\npin: 1\n")
        #expect(draft.otherFields.map(\.key) == ["pin"])
        draft.otherFields.append(.init(key: "note", value: "x"))
        #expect(draft.text == "pw\nurl: https://a.example\npin: 1\nnote: x\n")
    }

    @Test func passforiosOTPFieldsBecomeURI() throws {
        let draft = EntryDraft("pw\notp_secret: GEZDGNBVGY3TQOJQ\notp_digits: 8\n")
        let uri = try #require(draft.otpURI)
        #expect(uri.hasPrefix("otpauth://totp/"))
        #expect(Entry(draft.text).otp?.digits == 8)
        #expect(Entry(draft.text).otp?.secret == Data("12345678901234567890".prefix(10).utf8))
    }

    @Test func base32RoundTrip() {
        let data = Data("12345678901234567890".utf8)
        #expect(Base32.decode(Base32.encode(data)) == data)
    }
}

@Suite struct PasswordGeneratorTests {
    @Test func includesEveryClass() {
        for _ in 0..<50 {
            var o = PasswordGenerator.Options()
            o.length = 8
            let p = PasswordGenerator.password(o)
            #expect(p.count == 8)
            #expect(p.contains(where: \.isLowercase) && p.contains(where: \.isUppercase) && p.contains(where: \.isNumber))
            #expect(p.contains { PasswordGenerator.specials.contains($0) })
        }
    }

    @Test func passphrase() {
        #expect(PasswordGenerator.wordlist.count == 7776)
        #expect(PasswordGenerator.wordlist.contains("false"), "official list, not passforios' FALSE")
        var o = PasswordGenerator.PassphraseOptions()
        o.words = 4
        o.capitalize = true
        let p = PasswordGenerator.passphrase(o)
        #expect(p.split(separator: "-").count == 4)
        #expect(p.split(separator: "-").allSatisfy { $0.first!.isUppercase })
        #expect(PasswordGenerator.entropy(o) > 51 && PasswordGenerator.entropy(o) < 52)
    }
}

@Suite struct StoreWriteTests {
    let root = FileManager.default.temporaryDirectory.appending(path: "write-\(UUID().uuidString)", directoryHint: .isDirectory)
    let a = X25519Identity()
    let b = X25519Identity()

    init() throws {
        try FileManager.default.createDirectory(at: root.appending(path: "shared"), withIntermediateDirectories: true)
        try Data("\(a.recipient.encoded)\n".utf8).write(to: root.appending(path: ".age-recipients"))
        try Data("\(a.recipient.encoded)\n\(b.recipient.encoded)\n".utf8).write(to: root.appending(path: "shared/.age-recipients"))
    }

    @Test func saveEncryptsToNearestRecipients() async throws {
        let store = LocalStore(root: root)
        try await store.save(EntryPath("shared/wifi"), plaintext: Data("pw\n".utf8))
        let ct = try await store.read(EntryPath("shared/wifi"))
        #expect(try Age.decrypt(ct, identities: [b]) == Data("pw\n".utf8))
        try await store.save(EntryPath("deep/new/bank"), plaintext: Data("x\n".utf8))
        #expect(throws: AgeError.self) { try Age.decrypt(try Data(contentsOf: store.url(for: EntryPath("deep/new/bank"))), identities: [b]) }
    }

    @Test func moveReencryptsWhenRecipientsDiffer() async throws {
        let store = LocalStore(root: root)
        try await store.save(EntryPath("mine/bank"), plaintext: Data("secret\n".utf8))
        let a = self.a
        try await store.move(EntryPath("mine/bank"), to: EntryPath("shared/bank")) { try Age.decrypt($0, identities: [a]) }
        #expect(!FileManager.default.fileExists(atPath: root.appending(path: "mine").path), "empty folder removed")
        #expect(try Age.decrypt(await store.read(EntryPath("shared/bank")), identities: [b]) == Data("secret\n".utf8))

        // Same recipients: a plain rename, no decryption needed.
        try await store.move(EntryPath("shared/bank"), to: EntryPath("shared/bank2")) { _ in
            Issue.record("should not decrypt")
            return Data()
        }
        #expect(store.exists(EntryPath("shared/bank2")))
    }

    @Test func noRecipientsIsAnError() async throws {
        try FileManager.default.removeItem(at: root.appending(path: ".age-recipients"))
        await #expect(throws: StoreError.self) { try await LocalStore(root: root).save(EntryPath("x"), plaintext: Data()) }
    }

    @Test func deleteRemovesEmptyFolders() async throws {
        let store = LocalStore(root: root)
        try await store.save(EntryPath("a/b/c"), plaintext: Data("x".utf8))
        try await store.delete(EntryPath("a/b/c"))
        #expect(!FileManager.default.fileExists(atPath: root.appending(path: "a").path))
    }
}

@Suite struct RecipientManagementTests {
    let root = FileManager.default.temporaryDirectory.appending(path: "rcpt-\(UUID().uuidString)", directoryHint: .isDirectory)

    @Test func addsToEveryFileMatchingPostQuantumness() async throws {
        let classic = X25519Identity().recipient.encoded
        let pq = try HybridIdentity().recipient.encoded
        try FileManager.default.createDirectory(at: root.appending(path: "work/.git"), withIntermediateDirectories: true)
        try Data("# me\n\(classic)".utf8).write(to: root.appending(path: ".age-recipients"))
        try Data("\(pq)\n".utf8).write(to: root.appending(path: "work/.age-recipients"))
        try Data("\(classic)\n".utf8).write(to: root.appending(path: "work/.git/.age-recipients"))
        let store = LocalStore(root: root)
        #expect(store.recipientsFiles() == ["", "work"])

        let device = TagIdentity(key: try SoftwareTagKey(postQuantum: true))
        let forms: Set = [device.classicRecipient.encoded, device.postQuantumRecipient!.encoded]
        let changed = try await store.addRecipient(present: forms, comment: "iPhone (Passage)") { existing in
            existing.contains { $0.labels.contains("postquantum") } ? device.postQuantumRecipient!.encoded : device.classicRecipient.encoded
        }
        #expect(changed == ["", "work"])
        let top = try String(contentsOf: root.appending(path: ".age-recipients"), encoding: .utf8)
        #expect(top == "# me\n\(classic)\n# iPhone (Passage)\n\(device.classicRecipient.encoded)\n")
        #expect(try RecipientParser.parseFile(String(contentsOf: root.appending(path: "work/.age-recipients"), encoding: .utf8)).map(\.encoded) == [pq, device.postQuantumRecipient!.encoded])

        // Idempotent.
        #expect(try await store.addRecipient(present: forms, comment: "again") { _ in "x" }.isEmpty)

        // And encrypting to the updated files works (no PQ/classic mix).
        try await store.save(EntryPath("work/vpn"), plaintext: Data("v".utf8))
        try await store.save(EntryPath("bank"), plaintext: Data("b".utf8))
        let headers = await store.headers(of: [EntryPath("work/vpn"), EntryPath("bank")])
        #expect(headers.values.allSatisfy { device.classicRecipient.canDecrypt($0) })
    }
}

@Suite struct AutoFillTests {
    @Test func guessesFromPaths() {
        #expect(AutoFillIndex.guess(EntryPath("github.com/alice")) == .init(path: "github.com/alice", domains: ["github.com"], username: "alice", hasOTP: false, fromContent: false))
        #expect(AutoFillIndex.guess(EntryPath("email/Fastmail.com")).domains == ["fastmail.com"])
        #expect(AutoFillIndex.guess(EntryPath("email/Fastmail.com")).username == nil)
        #expect(AutoFillIndex.guess(EntryPath("bank")).domains.isEmpty)
        #expect(AutoFillIndex.guess(EntryPath("version 1.2/x")).domains.isEmpty, "numeric TLDs aren't hosts")
    }

    @Test func learnsFromContentAndKeepsIt() {
        var index = AutoFillIndex().updated(for: [EntryPath("bank"), EntryPath("github.com/alice")])
        index.learn(EntryPath("bank"), from: Entry("pw\nusername: 1234\nurl: https://online.bank.example/login\notpauth://totp/x?secret=JBSWY3DPEHPK3PXP"))
        let bank = index.items.first { $0.path == "bank" }!
        #expect(bank.domains == ["online.bank.example"] && bank.username == "1234" && bank.hasOTP && bank.fromContent)
        // Refreshing keeps learned items, drops deleted entries, adds new ones.
        let next = index.updated(for: [EntryPath("bank"), EntryPath("new.example/bob")])
        #expect(next.items.map(\.path) == ["bank", "new.example/bob"])
        #expect(next.items[0].fromContent)
    }

    @Test func matching() {
        let items = [
            AutoFillIndex.guess(EntryPath("github.com/alice")),
            AutoFillIndex.guess(EntryPath("work/gist.github.com")),
            AutoFillIndex.guess(EntryPath("evilgithub.com/x")),
            AutoFillIndex.guess(EntryPath("accounts.example.com/bob")),
        ]
        #expect(AutoFillMatcher.match(items, service: "https://github.com/login").map(\.path) == ["github.com/alice", "work/gist.github.com"])
        #expect(AutoFillMatcher.match(items, service: "gist.github.com").map(\.path) == ["work/gist.github.com", "github.com/alice"])
        #expect(AutoFillMatcher.match(items, service: "https://www.github.com").first?.path == "github.com/alice")
        #expect(AutoFillMatcher.match(items, service: "example.com").map(\.path) == ["accounts.example.com/bob"])
        #expect(AutoFillMatcher.match(items, service: "hub.com").isEmpty)
    }
}

@Suite struct PasskeyTests {
    @Test func entryRoundTrip() throws {
        let passkey = Passkey.create(relyingParty: "github.com", userName: "alice", userHandle: Data("user-123".utf8))
        let text = passkey.entryText
        #expect(text.hasPrefix("\nusername: alice\nurl: https://github.com\nKPEX_PASSKEY_RELYING_PARTY: github.com\n"))
        #expect(text.contains("KPEX_PASSKEY_PRIVATE_KEY_PEM: |\n  -----BEGIN PRIVATE KEY-----\n"))
        #expect(Passkey(entry: Entry(text)) == passkey)
        #expect(passkey.suggestedPath.path == "passkeys/github.com/alice")
        #expect(Passkey(entry: Entry("pw\nusername: x")) == nil)
    }

    @Test func cbor() {
        #expect(CBOR.int(-7) == Data([0x26]))
        #expect(CBOR.int(500) == Data([0x19, 0x01, 0xF4]))
        #expect(CBOR.text("fmt") == Data([0x63, 0x66, 0x6D, 0x74]))
        #expect(CBOR.map([]) == Data([0xA0]))
    }

    @Test func assertionVerifiesWithCryptoKit() throws {
        let passkey = Passkey.create(relyingParty: "example.com", userName: "bob", userHandle: Data([1, 2, 3]))
        let clientDataHash = Data(SHA256.hash(data: Data("client data".utf8)))
        let (authData, signature) = try passkey.assertion(clientDataHash: clientDataHash)
        #expect(authData.count == 37)
        #expect(authData[32] == 0x1D, "UP | UV | BE | BS")
        let sig = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(passkey.privateKey.publicKey.isValidSignature(sig, for: authData + clientDataHash))
    }

    /// Full registration + authentication checked by py_webauthn, an independent server-side
    /// implementation. Needs `uv` (and network the first time); skipped otherwise.
    @Test(.enabled(if: FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/uv")))
    func verifiedByPyWebAuthn() throws {
        let rpId = "example.com", origin = "https://example.com"
        let passkey = Passkey.create(relyingParty: rpId, userName: "alice", userHandle: Data("handle".utf8))
        func clientData(_ type: String, _ challenge: Data) -> Data {
            Data(#"{"type":"\#(type)","challenge":"\#(Base64URL.encode(challenge))","origin":"\#(origin)","crossOrigin":false}"#.utf8)
        }
        let regChallenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let authChallenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let regClient = clientData("webauthn.create", regChallenge)
        let authClient = clientData("webauthn.get", authChallenge)
        let (authData, signature) = try passkey.assertion(clientDataHash: Data(SHA256.hash(data: authClient)))
        let id = Base64URL.encode(passkey.credentialID)
        let input: [String: Any] = [
            "rpId": rpId, "origin": origin,
            "registrationChallenge": Base64URL.encode(regChallenge), "authenticationChallenge": Base64URL.encode(authChallenge),
            "registration": ["id": id, "rawId": id, "type": "public-key", "response": [
                "clientDataJSON": Base64URL.encode(regClient), "attestationObject": Base64URL.encode(passkey.attestationObject()),
            ]],
            "authentication": ["id": id, "rawId": id, "type": "public-key", "response": [
                "clientDataJSON": Base64URL.encode(authClient), "authenticatorData": Base64URL.encode(authData),
                "signature": Base64URL.encode(signature), "userHandle": Base64URL.encode(passkey.userHandle),
            ]],
        ]
        let file = FileManager.default.temporaryDirectory.appending(path: "webauthn-\(UUID().uuidString).json")
        try JSONSerialization.data(withJSONObject: input).write(to: file)

        let p = Process()
        p.executableURL = URL(filePath: "/opt/homebrew/bin/uv")
        let script = Bundle.module.url(forResource: "verify_webauthn", withExtension: "py")!
        p.arguments = ["run", "--quiet", "--with", "webauthn==2.*", "python", "-I", script.path, file.path]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        p.waitUntilExit()
        let output = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let errors = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(p.terminationStatus == 0, "\(errors)")
        #expect(output.contains(#""ok": true"#))
        #expect(output.contains(#""userVerified": true"#))
        #expect(output.contains(#""backedUp": true"#))
        #expect(output.lowercased().contains(Passkey.aaguid.uuidString.lowercased()))
    }
}

@Suite struct ProcessLockTests {
    @Test func excludesConcurrentHolders() async throws {
        let lock = ProcessLock(path: FileManager.default.temporaryDirectory.appending(path: "lock-\(UUID().uuidString)").path)
        let log = LockLog()
        async let first: Void = lock.withLock {
            await log.add("first in")
            try await Task.sleep(for: .milliseconds(200))
            await log.add("first out")
        }
        try await Task.sleep(for: .milliseconds(50))
        try await lock.withLock { await log.add("second in") }
        try await first
        #expect(await log.events == ["first in", "first out", "second in"])
    }

    @Test func timesOut() async throws {
        let lock = ProcessLock(path: FileManager.default.temporaryDirectory.appending(path: "lock-\(UUID().uuidString)").path)
        try await lock.withLock {
            await #expect(throws: ProcessLock.LockTimeout.self) { try await lock.withLock(timeout: .milliseconds(100)) {} }
        }
    }

    actor LockLog {
        var events: [String] = []
        func add(_ e: String) { events.append(e) }
    }
}

@Suite struct PasskeyIndexTests {
    @Test func learnsAndMatchesPasskeys() {
        let passkey = Passkey.create(relyingParty: "github.com", userName: "alice", userHandle: Data([7]))
        var index = AutoFillIndex().updated(for: [passkey.suggestedPath, EntryPath("github.com/alice")])
        index.learn(passkey.suggestedPath, from: Entry(passkey.entryText))
        let items = index.items
        #expect(AutoFillMatcher.passkeys(items, relyingParty: "github.com").map(\.path) == ["passkeys/github.com/alice"])
        #expect(AutoFillMatcher.passkeys(items, relyingParty: "GitHub.com", allowed: [passkey.credentialID]).count == 1)
        #expect(AutoFillMatcher.passkeys(items, relyingParty: "github.com", allowed: [Data([1, 2])]).isEmpty)
        #expect(AutoFillMatcher.passkeys(items, relyingParty: "gist.github.com").isEmpty, "exact RP ID only")
    }
}

@Suite struct CredentialImportTests {
    @Test func loginsAndPasskeys() {
        var github = ImportedItem(title: "GitHub")
        github.urls = ["https://github.com/login"]
        github.userName = "alice"
        github.password = "pw"
        github.otp = OTP(kind: .totp(period: 30), secret: Data("12345678901234567890".utf8), issuer: "GitHub", account: "alice")
        github.notes = ["recovery: in the safe"]
        let passkey = Passkey.create(relyingParty: "github.com", userName: "alice", userHandle: Data([1]))
        github.passkeys = [passkey]
        var wifi = ImportedItem(title: "../Home WiFi")
        wifi.password = "hunter2"

        let entries = CredentialImport.entries(for: [github, wifi], existing: [EntryPath("imported/github.com/alice")])
        #expect(entries.map(\.path.path) == ["imported/github.com/alice-2", "passkeys/github.com/alice", "imported/_home wifi/login"])
        let login = Entry(entries[0].text)
        #expect(login.password == "pw" && login.username == "alice" && login.url == "https://github.com/login")
        #expect(login.otp?.code(at: Date(timeIntervalSince1970: 59)) == OTP(kind: .totp(period: 30), secret: Data("12345678901234567890".utf8)).code(at: Date(timeIntervalSince1970: 59)))
        #expect(login.fields.contains { $0.key == "notes" && $0.value == "recovery: in the safe" })
        #expect(Passkey(entry: Entry(entries[1].text)) == passkey)
        #expect(!entries[2].path.path.contains(".."), "titles can't escape the folder")
    }
}

@Suite struct PasskeySignalTests {
    @Test func unknownAndAccepted() {
        let a = Passkey.create(relyingParty: "example.com", userName: "u", userHandle: Data([1]))
        let b = Passkey.create(relyingParty: "example.com", userName: "u", userHandle: Data([1]))
        var index = AutoFillIndex().updated(for: [EntryPath("passkeys/example.com/a"), EntryPath("passkeys/example.com/b")])
        index.learn(EntryPath("passkeys/example.com/a"), from: Entry(a.entryText))
        index.learn(EntryPath("passkeys/example.com/b"), from: Entry(b.entryText))

        index.markUnknown(relyingParty: "example.com", credentialID: a.credentialID)
        #expect(AutoFillMatcher.passkeys(index.items, relyingParty: "example.com", stale: index.staleCredentialIDs ?? []).map(\.path) == ["passkeys/example.com/b"])
        index.markUnknown(relyingParty: "other.com", credentialID: b.credentialID)
        #expect(index.staleCredentialIDs == [a.credentialID], "only for the matching RP")

        // The site now accepts a again but not b.
        index.markAccepted(relyingParty: "example.com", userHandle: Data([1]), accepted: [a.credentialID])
        #expect(index.staleCredentialIDs == [b.credentialID])
        #expect(index.updated(for: index.items.map { EntryPath($0.path) }).staleCredentialIDs == [b.credentialID], "kept across refreshes")

        index.rename(relyingParty: "example.com", userHandle: Data([1]), to: "new name")
        #expect(index.items.allSatisfy { $0.passkey?.userName == "new name" })
    }
}

@Suite struct NewStoreTests {
    @Test(arguments: [true, false]) func recoveryKitDecryptsTheNewStore(postQuantum: Bool) throws {
        let device = postQuantum ? try HybridIdentity().recipient.encoded : X25519Identity().recipient.encoded
        let kit = try RecoveryKit(postQuantum: postQuantum)
        #expect(kit.isPostQuantum == postQuantum)
        let files = NewStore.files(deviceRecipient: device, deviceName: "iPhone", recovery: kit)
        #expect(files.map(\.path) == [".age-recipients", "README.md"])

        let recipients = try RecipientParser.parseFile(files[0].contents)
        #expect(recipients.map(\.encoded) == [device, kit.recipient])
        let ciphertext = try Age.encrypt(Data("secret".utf8), to: recipients)
        // The kit file is a plain age identity file.
        let identities = try IdentityParser.parseFile(kit.file(store: "elohmeier/passwords"))
        #expect(try Age.decrypt(ciphertext, identities: identities) == Data("secret".utf8))
        #expect(kit.identity.hasSuffix(kit.confirmationSuffix) && kit.confirmationSuffix.count == 6)
    }

    @Test func emptiness() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "new-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: root.appending(path: ".git"), withIntermediateDirectories: true)
        try Data("# hello".utf8).write(to: root.appending(path: "README.md"))
        try Data().write(to: root.appending(path: ".git/x.age"))
        #expect(NewStore.isEmpty(at: root))
        try FileManager.default.createDirectory(at: root.appending(path: "a"), withIntermediateDirectories: true)
        try Data().write(to: root.appending(path: "a/b.age"))
        #expect(!NewStore.isEmpty(at: root))
    }
}

extension NewStoreTests {
    @Test func setUpWritesOnceAndKeepsReadme() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "new-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("# mine".utf8).write(to: root.appending(path: "README.md"))
        let kit = try RecoveryKit(postQuantum: false)
        let files = NewStore.files(deviceRecipient: X25519Identity().recipient.encoded, deviceName: "iPhone", recovery: kit)
        let store = LocalStore(root: root)
        try await store.setUp(files: files)
        #expect(try String(contentsOf: root.appending(path: "README.md"), encoding: .utf8) == "# mine")
        #expect(try await store.recipients(for: EntryPath("x")).count == 2)
        await #expect(throws: StoreError.alreadySetUp) { try await store.setUp(files: files) }
    }
}
