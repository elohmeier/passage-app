import CryptoKit
import Foundation

/// The age payload: STREAM over ChaCha20-Poly1305 in 64 KiB chunks. See https://c2sp.org/age#payload.
enum PayloadStream {
    static let nonceSize = 16
    static let chunkSize = 64 * 1024
    static let encryptedChunkSize = chunkSize + Primitives.tagSize

    static func key(fileKey: Data, nonce: Data) -> SymmetricKey {
        Primitives.hkdf(ikm: fileKey, salt: nonce, info: "payload")
    }

    private static func chunkNonce(_ counter: UInt64, last: Bool) -> ChaChaPoly.Nonce {
        var n = [UInt8](repeating: 0, count: 12)
        for i in 0..<8 {
            n[3 + i] = UInt8(truncatingIfNeeded: counter >> UInt64(8 * (7 - i)))
        }
        n[11] = last ? 1 : 0
        return try! ChaChaPoly.Nonce(data: n)
    }

    static func encrypt(_ plaintext: Data, key: SymmetricKey) -> Data {
        var out = Data()
        out.reserveCapacity(plaintext.count + (plaintext.count / chunkSize + 1) * Primitives.tagSize)
        var counter: UInt64 = 0
        var start = plaintext.startIndex
        repeat {
            let end = plaintext.index(start, offsetBy: chunkSize, limitedBy: plaintext.endIndex) ?? plaintext.endIndex
            let last = end == plaintext.endIndex
            let box = try! ChaChaPoly.seal(plaintext[start..<end], using: key, nonce: chunkNonce(counter, last: last))
            out.append(box.ciphertext)
            out.append(box.tag)
            counter += 1
            start = end
        } while start != plaintext.endIndex
        return out
    }

    /// Decrypts `ciphertext`, handing each authenticated chunk to `sink` as soon as it's verified.
    /// On failure, everything passed to `sink` so far is authentic but the file is incomplete.
    static func decrypt(_ ciphertext: Data, key: SymmetricKey, sink: (Data) -> Void) throws(AgeError) {
        var counter: UInt64 = 0
        var offset = ciphertext.startIndex
        while true {
            let available = ciphertext.endIndex - offset
            guard available > 0 else { throw .payload("unexpected EOF") }
            let n = min(available, encryptedChunkSize)
            let chunk = ciphertext[offset..<(offset + n)]
            offset += n

            var last = n < encryptedChunkSize
            if last && counter != 0 && n == Primitives.tagSize {
                throw .payload("last chunk is empty")
            }
            guard n >= Primitives.tagSize else { throw .payload("chunk too short") }

            var plaintext = open(chunk, key: key, nonce: chunkNonce(counter, last: last))
            if plaintext == nil && !last {
                // A full chunk may also be the final one.
                last = true
                plaintext = open(chunk, key: key, nonce: chunkNonce(counter, last: true))
            }
            guard let plaintext else { throw .payload("failed to decrypt and authenticate payload chunk") }
            sink(plaintext)
            counter += 1

            if last {
                guard offset == ciphertext.endIndex else { throw .payload("trailing data after end of encrypted file") }
                return
            }
        }
    }

    private static func open(_ chunk: Data, key: SymmetricKey, nonce: ChaChaPoly.Nonce) -> Data? {
        guard let box = try? ChaChaPoly.SealedBox(
            nonce: nonce, ciphertext: chunk.dropLast(Primitives.tagSize), tag: chunk.suffix(Primitives.tagSize))
        else { return nil }
        return try? ChaChaPoly.open(box, using: key)
    }
}
