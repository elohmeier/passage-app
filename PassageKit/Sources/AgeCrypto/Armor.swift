import Foundation

/// The optional ASCII armor (strict PEM). See https://c2sp.org/age#ascii-armor.
public enum Armor {
    static let header = "-----BEGIN AGE ENCRYPTED FILE-----"
    static let footer = "-----END AGE ENCRYPTED FILE-----"
    private static let maxWhitespace = 1024
    private static let whitespace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]

    public static func encode(_ data: Data) -> Data {
        let b64 = Base64.encode(data, padded: true)
        var out = header + "\n"
        var i = b64.startIndex
        while i != b64.endIndex {
            let end = b64.index(i, offsetBy: Header.columnsPerLine, limitedBy: b64.endIndex) ?? b64.endIndex
            out += b64[i..<end] + "\n"
            i = end
        }
        out += footer + "\n"
        return Data(out.utf8)
    }

    /// True if `data` looks like an armored age file (leading whitespace is allowed).
    public static func isArmored(_ data: Data) -> Bool {
        let trimmed = data.prefix(maxWhitespace + header.utf8.count).drop { whitespace.contains($0) }
        return trimmed.starts(with: Array(header.utf8))
    }

    public static func decode(_ data: Data) throws(AgeError) -> Data {
        var reader = LineReader(bytes: [UInt8](data))

        // Lines without the trailing "\n" or "\r\n". A final line without a newline is accepted.
        func nextLine() throws(AgeError) -> [UInt8] {
            var line: [UInt8]
            if let l = reader.readLine() {
                line = l
                line.removeLast()
            } else if reader.remaining > 0 {
                line = reader.peek(reader.remaining)
                reader = LineReader(bytes: [])
            } else {
                throw .armor("unexpected EOF")
            }
            if line.last == UInt8(ascii: "\r") { line.removeLast() }
            return line
        }

        func checkTrailing() throws(AgeError) {
            let rest = reader.peek(reader.remaining)
            guard rest.allSatisfy(whitespace.contains) else { throw .armor("trailing data after armored file") }
            guard rest.count < maxWhitespace else { throw .armor("too much trailing whitespace") }
        }

        var skipped = 0
        while true {
            let line = try nextLine()
            if line.allSatisfy(whitespace.contains) {
                skipped += line.count + 1
                guard skipped <= maxWhitespace else { throw .armor("too much leading whitespace") }
                continue
            }
            guard line == Array(header.utf8) else { throw .armor("invalid first line") }
            break
        }

        var out = Data()
        while true {
            let line = try nextLine()
            if line == Array(footer.utf8) {
                try checkTrailing()
                return out
            }
            guard !line.isEmpty else { throw .armor("empty line in armored data") }
            guard line.count <= Header.columnsPerLine else { throw .armor("column limit exceeded") }
            guard let chunk = Base64.decode(line, padded: true) else { throw .armor("invalid base64") }
            out.append(chunk)
            if chunk.count < Header.bytesPerLine {
                guard try nextLine() == Array(footer.utf8) else { throw .armor("invalid closing line") }
                try checkTrailing()
                return out
            }
        }
    }
}
