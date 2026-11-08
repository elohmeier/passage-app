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
