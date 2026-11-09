import AgeCrypto
import Foundation

/// A recovery identity for a new store: an age key that is shown once, kept by the user on
/// paper or in another password manager, and never stored by the app. With it, the store can
/// be decrypted with plain `age`/`passage` if every device key is lost.
public struct RecoveryKit: Sendable, Equatable {
    public let identity: String
    public let recipient: String
    public let created: Date

    public init(postQuantum: Bool, created: Date = .now) throws {
        if postQuantum {
            let identity = try HybridIdentity()
            self.identity = identity.encoded
            recipient = identity.recipient.encoded
        } else {
            let identity = X25519Identity()
            self.identity = identity.encoded
            recipient = identity.recipient.encoded
        }
        self.created = created
    }

    public var isPostQuantum: Bool { recipient.hasPrefix("age1pq1") }

    /// An age identity file, as written by `age-keygen`: usable as-is with
    /// `PASSAGE_IDENTITIES_FILE` or `age -d -i`.
    public func file(store: String) -> String {
        """
        # Passage recovery key for \(store)
        # created: \(created.ISO8601Format())
        # public key: \(recipient)
        \(identity)

        """
    }

    /// The last characters of the secret key, which the user types back to show they saved it.
    public var confirmationSuffix: String { String(identity.suffix(6)) }
}

public enum NewStore {
    /// True if `root` has nothing a store would have: no `.age-recipients` and no entries,
    /// counting iCloud placeholders of either. Other files (a README GitHub created, a
    /// license) don't count.
    public static func isEmpty(at root: URL) -> Bool {
        guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else { return true }
        for case let url as URL in walker {
            var name = url.lastPathComponent
            if name == ".git" {
                walker.skipDescendants()
                continue
            }
            if name.hasPrefix("."), name.hasSuffix(".icloud") { name = String(name.dropFirst().dropLast(7)) }
            if name == ".age-recipients" || (name.hasSuffix(".age") && !name.hasPrefix(".")) { return false }
        }
        return true
    }

    /// The files of a new store: `.age-recipients` with the device and recovery recipients,
    /// and a README, unless one exists.
    public static func files(
        deviceRecipient: String, deviceName: String, recovery: RecoveryKit, includeReadme: Bool = true
    ) -> [(path: String, contents: String)] {
        let day = recovery.created.formatted(.iso8601.year().month().day())
        var files = [
            (
                ".age-recipients",
                """
                # \(deviceName) (Passage, \(day))
                \(deviceRecipient)
                # Recovery key (\(day))
                \(recovery.recipient)

                """
            )
        ]
        if includeReadme {
            files.append(
                (
                    "README.md",
                    """
                    # Password store

                    A [passage](https://github.com/FiloSottile/passage) store: each entry is an [age](https://age-encryption.org)-encrypted file, encrypted to the recipients in `.age-recipients`.

                    Created with Passage for iOS. To use it on a computer, clone it to `~/.passage/store`, add your computer's recipient to `.age-recipients`, and re-encrypt the entries using the recovery key:

                    ```
                    PASSAGE_IDENTITIES_FILE=recovery-key.txt passage reencrypt
                    ```

                    """
                ))
        }
        return files
    }
}

extension LocalStore {
    /// Writes a new store's files. Refuses if the store already has a `.age-recipients`;
    /// keeps an existing README.
    public func setUp(files: [(path: String, contents: String)]) async throws {
        guard NewStore.isEmpty(at: root) else { throw StoreError.alreadySetUp }
        for file in files {
            let url = root.appending(path: file.path)
            if file.path == "README.md", FileManager.default.fileExists(atPath: url.path) { continue }
            try await coordinated(writing: url) { try Data(file.contents.utf8).write(to: $0, options: .withoutOverwriting) }
        }
    }
}
