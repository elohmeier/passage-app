import Foundation
import Testing

@testable import AgeCrypto

/// Round trips with the reference `age` CLI (v1.3+). Skipped if it isn't installed.
@Suite(.enabled(if: CLI.path("age") != nil && CLI.path("age-keygen") != nil))
struct InteropTests {
    let message = Data("hunter2\nurl: https://example.com\n".utf8)

    @Test(arguments: [false, true])
    func cliEncryptsWeDecrypt(postQuantum: Bool) throws {
        let keyFile = try CLI.temp()
        try CLI.run("age-keygen", postQuantum ? ["-pq", "-o", keyFile.path] : ["-o", keyFile.path])
        let identities = try IdentityParser.parseFile(String(contentsOf: keyFile, encoding: .utf8))
        let ct = try CLI.run("age", ["-e", "-i", keyFile.path], input: message)
        #expect(try Age.decrypt(ct, identities: identities) == message)
    }

    @Test(arguments: [false, true])
    func weEncryptCLIDecrypts(postQuantum: Bool) throws {
        let keyFile = try CLI.temp()
        let identity: String
        let recipient: any AgeRecipient
        if postQuantum {
            let id = try HybridIdentity()
            (identity, recipient) = (id.encoded, id.recipient)
        } else {
            let id = X25519Identity()
            (identity, recipient) = (id.encoded, id.recipient)
        }
        try Data((identity + "\n").utf8).write(to: keyFile)
        for armor in [false, true] {
            let ct = try Age.encrypt(message, to: [recipient], armor: armor)
            #expect(try CLI.run("age", ["-d", "-i", keyFile.path], input: ct) == message)
        }
    }

    /// age ≥ 1.3 encrypts to tagged recipients natively; we decrypt with the matching key.
    @Test(arguments: [false, true])
    func cliEncryptsToTagRecipient(postQuantum: Bool) throws {
        let id = TagIdentity(key: try SoftwareTagKey(postQuantum: postQuantum))
        let recipient = postQuantum ? id.postQuantumRecipient! : id.classicRecipient
        let ct = try CLI.run("age", ["-e", "-r", recipient.encoded], input: message)
        #expect(try Age.decrypt(ct, identities: [id]) == message)
    }

    @Test func largeFile() throws {
        let keyFile = try CLI.temp()
        try CLI.run("age-keygen", ["-o", keyFile.path])
        let ids = try IdentityParser.parseFile(String(contentsOf: keyFile, encoding: .utf8))
        let recipient = try CLI.run("age-keygen", ["-y", keyFile.path])
        let plaintext = Primitives.randomBytes(5 * 65536 + 123)
        let ct = try Age.encrypt(plaintext, to: [RecipientParser.parse(String(decoding: recipient, as: UTF8.self))])
        #expect(try CLI.run("age", ["-d", "-i", keyFile.path], input: ct) == plaintext)
        let ct2 = try CLI.run("age", ["-e", "-i", keyFile.path], input: plaintext)
        #expect(try Age.decrypt(ct2, identities: ids) == plaintext)
    }
}

enum CLI {
    static func path(_ name: String) -> String? {
        let dirs = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":")
            + ["/opt/homebrew/bin", "/usr/local/bin"]
        return dirs.map { "\($0)/\(name)" }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static func temp() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "agecrypto-\(UUID().uuidString)")
        return url
    }

    @discardableResult
    static func run(_ tool: String, _ args: [String], input: Data = Data()) throws -> Data {
        let p = Process()
        p.executableURL = URL(filePath: path(tool)!)
        p.arguments = args
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        p.standardInput = stdin
        p.standardOutput = stdout
        p.standardError = stderr
        try p.run()
        // Write stdin and read stdout concurrently so large payloads don't deadlock on the pipes.
        let writer = Thread {
            stdin.fileHandleForWriting.write(input)
            try? stdin.fileHandleForWriting.close()
        }
        writer.start()
        let out = stdout.fileHandleForReading.readDataToEndOfFile()
        let err = stderr.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            throw CLIError(message: "\(tool) \(args.joined(separator: " ")): \(String(decoding: err, as: UTF8.self))")
        }
        return out
    }

    struct CLIError: Error, CustomStringConvertible {
        let message: String
        var description: String { message }
    }
}
