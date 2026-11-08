import CryptoKit
import Foundation
import Testing

@testable import AgeCrypto

/// Runs the C2SP/CCTV age test vectors (see testkit/SOURCE.txt), following the reference
/// harness in filippo.io/age's testkit_test.go.
struct Vector: CustomTestStringConvertible, Sendable {
    let name: String
    var expect = ""
    var payloadHash: Data?
    var fileKey: Data?
    var identities: [String] = []
    var passphrases: [String] = []
    var armored = false
    var file = Data()

    var testDescription: String { name }

    static let all: [Vector] = {
        let dir = Bundle.module.url(forResource: "testkit", withExtension: nil)!
        let names = try! FileManager.default.contentsOfDirectory(atPath: dir.path)
            .filter { !$0.hasSuffix(".txt") }.sorted()
        return names.map { try! Vector(name: $0, contents: Data(contentsOf: dir.appending(path: $0))) }
    }()

    init(name: String, contents: Data) throws {
        self.name = name
        var rest = contents[...]
        var compressed = false
        while true {
            let nl = rest.firstIndex(of: UInt8(ascii: "\n"))!
            let line = String(decoding: rest[..<nl], as: UTF8.self)
            rest = rest[(nl + 1)...]
            if line.isEmpty { break }
            let parts = line.split(separator: ": ", maxSplits: 1).map(String.init)
            let value = parts.count > 1 ? parts[1] : ""
            switch parts[0] {
            case "expect": expect = value
            case "payload": payloadHash = Data(hex: value)
            case "file key": fileKey = Data(hex: value)
            case "identity": identities.append(value)
            case "passphrase": passphrases.append(value)
            case "armored": armored = true
            case "compressed": compressed = true
            case "comment": break
            default: Issue.record("unknown header key \(parts[0])")
            }
        }
        file = Data(rest)
        if compressed {
            // zlib: strip the 2-byte header and 4-byte Adler-32 trailer, inflate raw DEFLATE.
            file = try (file.dropFirst(2).dropLast(4) as NSData).decompressed(using: .zlib) as Data
        }
    }

    func makeIdentities() throws -> [any AgeIdentity] {
        try identities.map { s -> any AgeIdentity in
            s.hasPrefix("AGE-SECRET-KEY-PQ-") ? try HybridIdentity(s) : try X25519Identity(s)
        } + passphrases.map { ScryptIdentity(passphrase: $0) }
    }
}

extension Data {
    init?(hex: String) {
        var bytes = [UInt8]()
        var it = hex.makeIterator()
        while let a = it.next(), let b = it.next() {
            guard let v = UInt8(String([a, b]), radix: 16) else { return nil }
            bytes.append(v)
        }
        self.init(bytes)
    }
}

@Suite struct TestkitTests {
    @Test(arguments: Vector.all)
    func decrypt(_ v: Vector) throws {
        var out = Data()
        let outcome: String
        do {
            // Armored vectors go through the armor decoder explicitly, like the reference harness.
            let input = v.armored ? try Armor.decode(v.file) : v.file
            try Age.decrypt(input, identities: v.makeIdentities()) { out.append($0) }
            outcome = "success"
        } catch let e as AgeError {
            switch e {
            case .armor: outcome = "armor failure"
            case .headerMAC: outcome = "HMAC failure"
            case .noIdentityMatch: outcome = "no match"
            case .payload: outcome = "payload failure"
            default: outcome = "header failure"
            }
            if outcome != v.expect { Issue.record("\(v.name): expected \(v.expect), got \(e)") }
        }
        #expect(outcome == v.expect, "\(v.name)")
        if outcome == "success" || outcome == "payload failure", let hash = v.payloadHash {
            #expect(Data(SHA256.hash(data: out)) == hash, "payload hash mismatch")
        }
    }

    @Test(arguments: Vector.all.filter { !$0.armored && $0.expect != "header failure" })
    func headerRoundTrip(_ v: Vector) throws {
        let (header, offset) = try Header.parse(v.file)
        #expect(header.encoded() + v.file.dropFirst(offset) == v.file)

        guard v.expect == "success", let fileKey = v.fileKey else { return }
        let payload = v.file.dropFirst(offset)
        let nonce = payload.prefix(16)
        let key = PayloadStream.key(fileKey: fileKey, nonce: nonce)
        var plaintext = Data()
        try PayloadStream.decrypt(payload.dropFirst(16), key: key) { plaintext.append($0) }
        #expect(PayloadStream.encrypt(plaintext, key: key) == payload.dropFirst(16), "STREAM round trip")
    }

    @Test(arguments: Vector.all.filter { $0.armored && $0.expect != "armor failure" })
    func armorRoundTrip(_ v: Vector) throws {
        let payload = try Armor.decode(v.file)
        var expect = String(decoding: v.file, as: UTF8.self).replacingOccurrences(of: "\r\n", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        expect += "\n"
        #expect(String(decoding: Armor.encode(payload), as: UTF8.self) == expect)
    }
}
