import Foundation

/// A recipient stanza: `-> type args…` followed by a base64 body.
public struct Stanza: Equatable, Sendable {
    public var type: String
    public var args: [String]
    public var body: Data

    public init(type: String, args: [String], body: Data) {
        self.type = type
        self.args = args
        self.body = body
    }
}

/// The age v1 header. See https://c2sp.org/age#header.
public struct Header: Equatable, Sendable {
    public var stanzas: [Stanza]
    public var mac: Data

    static let intro = Array("age-encryption.org/v1\n".utf8)
    static let columnsPerLine = 64
    static let bytesPerLine = columnsPerLine / 4 * 3
    static let maxHeaderBytes = 2 << 20
    static let maxStanzas = 1024
    static let maxStanzaArgs = 128

    /// The header up to and including `---`, which is what the MAC is computed over.
    func encodedWithoutMAC() -> Data {
        var out = Data(Self.intro)
        for s in stanzas {
            out.append(contentsOf: Array("-> \(([s.type] + s.args).joined(separator: " "))\n".utf8))
            let body = Base64.encode(s.body)
            var i = body.startIndex
            // A body always ends with a line shorter than 64 columns, possibly empty.
            while true {
                let end = body.index(i, offsetBy: Self.columnsPerLine, limitedBy: body.endIndex) ?? body.endIndex
                out.append(contentsOf: Array(body[i..<end].utf8))
                out.append(UInt8(ascii: "\n"))
                if body.distance(from: i, to: end) < Self.columnsPerLine { break }
                i = end
            }
        }
        out.append(contentsOf: Array("---".utf8))
        return out
    }

    func encoded() -> Data {
        encodedWithoutMAC() + Data(" \(Base64.encode(mac))\n".utf8)
    }

    /// Parses a header from the start of `data`, returning it and the offset of the payload.
    static func parse(_ data: Data) throws(AgeError) -> (header: Header, payloadOffset: Int) {
        var reader = LineReader(bytes: [UInt8](data.prefix(maxHeaderBytes + 1)))
        guard let intro = reader.readLine() else {
            throw .header(data.isEmpty ? "file is empty" : "unexpected EOF reading intro")
        }
        guard intro == Self.intro else { throw .header("unexpected intro") }

        var stanzas: [Stanza] = []
        while true {
            guard reader.remaining >= 3 else { throw .header("unexpected EOF") }
            if reader.peek(3) == Array("---".utf8) {
                guard let line = reader.readLine() else { throw .header("unexpected EOF in closing line") }
                let (prefix, args) = splitArgs(line)
                guard prefix == "---", let args, args.count == 1 else { throw .header("malformed closing line") }
                guard let mac = Base64.decode(args[0]), mac.count == 32 else { throw .header("malformed MAC") }
                guard !stanzas.isEmpty else { throw .header("no recipient stanzas") }
                guard reader.offset <= maxHeaderBytes else { throw .header("header exceeds 2 MiB") }
                return (Header(stanzas: stanzas, mac: mac), reader.offset)
            }
            guard stanzas.count < maxStanzas else { throw .header("too many recipient stanzas") }
            stanzas.append(try parseStanza(&reader))
        }
    }

    private static func parseStanza(_ reader: inout LineReader) throws(AgeError) -> Stanza {
        guard let line = reader.readLine() else { throw .header("unexpected EOF in stanza") }
        let (prefix, args) = splitArgs(line)
        guard prefix == "->", let args, !args.isEmpty else { throw .header("malformed stanza opening line") }

        var body = Data()
        while true {
            guard var line = reader.readLine() else { throw .header("unexpected EOF in stanza body") }
            line.removeLast()  // "\n"
            guard let chunk = Base64.decode(line) else { throw .header("malformed stanza body line") }
            guard chunk.count <= bytesPerLine else { throw .header("stanza body line too long") }
            body.append(chunk)
            if chunk.count < bytesPerLine {
                return Stanza(type: args[0], args: Array(args.dropFirst()), body: body)
            }
        }
    }

    /// Splits `prefix arg arg…\n`. Returns nil args if any argument is empty or contains
    /// characters outside VCHAR, mirroring the reference implementation.
    private static func splitArgs(_ line: [UInt8]) -> (String, [String]?) {
        let l = line.last == UInt8(ascii: "\n") ? line.dropLast() : line[...]
        guard let space = l.firstIndex(of: UInt8(ascii: " ")) else {
            return (String(decoding: l, as: UTF8.self), nil)
        }
        let prefix = String(decoding: l[..<space], as: UTF8.self)
        let parts = l[(space + 1)...].split(separator: UInt8(ascii: " "), omittingEmptySubsequences: false)
        guard parts.count <= maxStanzaArgs + 1, parts.allSatisfy(isValidArg) else { return (prefix, nil) }
        return (prefix, parts.map { String(decoding: $0, as: UTF8.self) })
    }

    static func isValidArg(_ s: some Collection<UInt8>) -> Bool {
        !s.isEmpty && s.allSatisfy { $0 >= 33 && $0 <= 126 }
    }
}

struct LineReader {
    let bytes: [UInt8]
    private(set) var offset = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    var remaining: Int { bytes.count - offset }

    func peek(_ n: Int) -> [UInt8] { Array(bytes[offset..<min(offset + n, bytes.count)]) }

    /// Returns the next line including its trailing `\n`, or nil if there is no complete line.
    mutating func readLine() -> [UInt8]? {
        guard let nl = bytes[offset...].firstIndex(of: UInt8(ascii: "\n")) else { return nil }
        defer { offset = nl + 1 }
        return Array(bytes[offset...nl])
    }
}
