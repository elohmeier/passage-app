import AgeCrypto
import CryptoKit
import Foundation
import LocalAuthentication

/// Metadata for a stored identity. Contains no secrets.
public struct StoredIdentity: Codable, Identifiable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable {
        /// Generated in this device's Secure Enclave. Can't be exported or backed up.
        case secureEnclave
        /// An imported `AGE-SECRET-KEY-…`, stored encrypted to its own Secure Enclave key.
        case imported
        /// A software tag key in the keychain. Only created in the Simulator, which has no
        /// Secure Enclave, so the app can be developed there.
        case simulator
    }

    public let id: UUID
    public var name: String
    public let kind: Kind
    public let protection: KeyProtection
    public let createdAt: Date
    /// Recipients that encrypt to this identity. Device keys have two: `age1tag1…` (classic)
    /// and `age1tagpq1…` (post-quantum); either can be decrypted.
    public let recipients: [String]

    /// The device key's recipient to add to a folder that already has `existing` recipients.
    /// age can't mix post-quantum and classic recipients in one file, so match what's there.
    public func recommendedRecipient(alongside existing: [any AgeRecipient]) -> String {
        let postQuantum = existing.isEmpty || existing.contains { $0.labels.contains("postquantum") }
        let pq = recipients.first { $0.hasPrefix("age1tagpq1") || $0.hasPrefix("age1pq1") }
        let classic = recipients.first { !($0.hasPrefix("age1tagpq1") || $0.hasPrefix("age1pq1")) }
        return (postQuantum ? pq ?? classic : classic ?? pq) ?? recipients[0]
    }
}

/// Creates, imports, lists and unlocks age identities.
///
/// Layout in the `SecretStore`:
/// - `index`: JSON array of `StoredIdentity`
/// - `<id>.p256`, `<id>.mlkem`: Secure Enclave key blobs (device keys, and the wrapping key of
///   imported identities). The Secure Enclave enforces their access control.
/// - `<id>.secret`: an imported identity, age-encrypted to the `<id>` Secure Enclave key
/// - `<id>.software`: Simulator only, the software key with keychain access control
public final class IdentityStore: Sendable {
    let store: any SecretStore
    let secureEnclaveAvailable: Bool

    public init(store: any SecretStore, secureEnclaveAvailable: Bool = SecureEnclave.isAvailable) {
        self.store = store
        self.secureEnclaveAvailable = secureEnclaveAvailable
    }

    // MARK: Index

    public func list() throws(KeyStoreError) -> [StoredIdentity] {
        guard let data = try store.get("index", context: nil) else { return [] }
        do {
            return try JSONDecoder().decode([StoredIdentity].self, from: data)
        } catch {
            throw .corrupted("identity index: \(error.localizedDescription)")
        }
    }

    private func save(_ index: [StoredIdentity]) throws(KeyStoreError) {
        let data: Data
        do {
            data = try JSONEncoder().encode(index)
        } catch {
            throw .corrupted("identity index: \(error.localizedDescription)")
        }
        try store.set(data, for: "index", accessControl: nil)
    }

    private func append(_ identity: StoredIdentity) throws(KeyStoreError) {
        try save(list() + [identity])
    }

    public func rename(_ id: UUID, to name: String) throws(KeyStoreError) {
        var index = try list()
        guard let i = index.firstIndex(where: { $0.id == id }) else { throw .notFound }
        index[i].name = name
        try save(index)
    }

    /// Deletes an identity and its key material. Secure Enclave keys are gone for good.
    public func delete(_ id: UUID) throws(KeyStoreError) {
        for suffix in ["p256", "mlkem", "secret", "software"] {
            try store.delete("\(id).\(suffix)")
        }
        try save(list().filter { $0.id != id })
    }

    // MARK: Creating

    /// Generates this device's identity: in the Secure Enclave, or as a software key in the
    /// Simulator.
    public func createDeviceIdentity(name: String, protection: KeyProtection) throws(KeyStoreError) -> StoredIdentity {
        let id = UUID()
        let tag: TagIdentity
        let kind: StoredIdentity.Kind
        if secureEnclaveAvailable {
            let key = try SecureEnclaveTagKey(protection: protection)
            try store.set(key.p256DataRepresentation, for: "\(id).p256", accessControl: nil)
            try store.set(key.mlkemDataRepresentation, for: "\(id).mlkem", accessControl: nil)
            tag = TagIdentity(key: key)
            kind = .secureEnclave
        } else {
            #if targetEnvironment(simulator)
                let key: SoftwareTagKey
                do {
                    key = try SoftwareTagKey(postQuantum: true)
                } catch {
                    throw .accessControl("key generation failed: \(error.localizedDescription)")
                }
                let blob = SoftwareKeyBlob(p256: key.p256RawRepresentation, mlkemSeed: key.mlkemSeed!)
                try store.set(blob.encoded, for: "\(id).software", accessControl: protection == .unprotected ? nil : protection.keychainAccessControl())
                tag = TagIdentity(key: key)
                kind = .simulator
            #else
                throw .secureEnclaveUnavailable
            #endif
        }
        let identity = StoredIdentity(
            id: id, name: name, kind: kind, protection: protection, createdAt: .now,
            recipients: [tag.classicRecipient.encoded, tag.postQuantumRecipient!.encoded])
        try append(identity)
        return identity
    }

    /// Imports the native identities in an identity file (`AGE-SECRET-KEY-…` lines). Each is
    /// stored encrypted to a fresh Secure Enclave key with the given protection, so the keychain
    /// alone isn't enough to recover it.
    public func importIdentities(_ text: String, name: String, protection: KeyProtection) throws(KeyStoreError) -> [StoredIdentity] {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        guard !lines.isEmpty else { throw .invalidIdentity("No identities found.") }

        // Validate everything before storing anything.
        var parsed: [(secret: String, recipient: String)] = []
        for line in lines {
            do {
                if line.hasPrefix("AGE-SECRET-KEY-PQ-1") {
                    parsed.append((line, try HybridIdentity(line).recipient.encoded))
                } else if line.hasPrefix("AGE-SECRET-KEY-1") {
                    parsed.append((line, try X25519Identity(line).recipient.encoded))
                } else {
                    throw AgeError.invalidEncoding(
                        line.hasPrefix("AGE-PLUGIN-") ? "Plugin identities can't be used on iOS." : "Unknown identity type.")
                }
            } catch {
                throw .invalidIdentity(error.localizedDescription)
            }
        }

        var imported: [StoredIdentity] = []
        for (i, (secret, recipient)) in parsed.enumerated() {
            let id = UUID()
            if secureEnclaveAvailable {
                let wrapper = try SecureEnclaveTagKey(protection: protection)
                let ciphertext: Data
                do {
                    ciphertext = try Age.encrypt(Data(secret.utf8), to: [TagIdentity(key: wrapper).postQuantumRecipient!])
                } catch {
                    throw .corrupted("wrapping failed: \(error.localizedDescription)")
                }
                try store.set(wrapper.p256DataRepresentation, for: "\(id).p256", accessControl: nil)
                try store.set(wrapper.mlkemDataRepresentation, for: "\(id).mlkem", accessControl: nil)
                try store.set(ciphertext, for: "\(id).secret", accessControl: nil)
            } else {
                #if targetEnvironment(simulator)
                    try store.set(Data(secret.utf8), for: "\(id).secret", accessControl: protection == .unprotected ? nil : protection.keychainAccessControl())
                #else
                    throw .secureEnclaveUnavailable
                #endif
            }
            let identity = StoredIdentity(
                id: id, name: parsed.count == 1 ? name : "\(name) \(i + 1)", kind: .imported, protection: protection,
                createdAt: .now, recipients: [recipient])
            try append(identity)
            imported.append(identity)
        }
        return imported
    }

    // MARK: Unlocking

    /// Loads usable age identities. Pass an authenticated `context` from `UnlockSessionManager`
    /// so the Secure Enclave and keychain don't prompt again.
    ///
    /// Device keys come first: they check stanza tags before using the key, so they only cost
    /// an authentication when a file is actually encrypted to them.
    public func unlock(_ identities: [StoredIdentity]? = nil, context: LAContext?) throws(KeyStoreError) -> [any AgeIdentity] {
        let selected = if let identities { identities } else { try list() }
        var out: [any AgeIdentity] = []
        for identity in selected.sorted(by: { ($0.kind == .imported ? 1 : 0) < ($1.kind == .imported ? 1 : 0) }) {
            out.append(try unlock(identity, context: context))
        }
        return out
    }

    private func unlock(_ identity: StoredIdentity, context: LAContext?) throws(KeyStoreError) -> any AgeIdentity {
        let id = identity.id
        switch identity.kind {
        case .secureEnclave:
            return TagIdentity(key: try secureEnclaveKey(id, context: context))

        case .simulator:
            guard let data = try store.get("\(id).software", context: context) else { throw .notFound }
            return TagIdentity(key: try SoftwareKeyBlob(data).key())

        case .imported:
            guard let stored = try store.get("\(id).secret", context: context) else { throw .notFound }
            let secret = secureEnclaveAvailable ? try unwrapImported(stored, wrapper: secureEnclaveKey(id, context: context)) : stored
            do {
                return try IdentityParser.parseFile(String(decoding: secret, as: UTF8.self))[0]
            } catch {
                throw .corrupted("imported identity: \(error.localizedDescription)")
            }
        }
    }

    private func unwrapImported(_ ciphertext: Data, wrapper: SecureEnclaveTagKey) throws(KeyStoreError) -> Data {
        do {
            return try Age.decrypt(ciphertext, identities: [TagIdentity(key: wrapper)])
        } catch .identityUnavailable(let message) {
            throw .authenticationFailed(message)
        } catch {
            throw .corrupted("imported identity: \(error.localizedDescription)")
        }
    }

    private func secureEnclaveKey(_ id: UUID, context: LAContext?) throws(KeyStoreError) -> SecureEnclaveTagKey {
        guard let p256 = try store.get("\(id).p256", context: nil), let mlkem = try store.get("\(id).mlkem", context: nil) else {
            throw .notFound
        }
        return try SecureEnclaveTagKey(p256Data: p256, mlkemData: mlkem, context: context)
    }
}

/// Simulator-only storage format for a software tag key.
struct SoftwareKeyBlob: Codable {
    let p256: Data
    let mlkemSeed: Data

    init(p256: Data, mlkemSeed: Data) {
        self.p256 = p256
        self.mlkemSeed = mlkemSeed
    }

    init(_ data: Data) throws(KeyStoreError) {
        do {
            self = try JSONDecoder().decode(Self.self, from: data)
        } catch {
            throw .corrupted("software key: \(error.localizedDescription)")
        }
    }

    var encoded: Data { try! JSONEncoder().encode(self) }

    func key() throws(KeyStoreError) -> SoftwareTagKey {
        do {
            return try SoftwareTagKey(p256RawRepresentation: p256, mlkemSeed: mlkemSeed)
        } catch {
            throw .corrupted("software key: \(error.localizedDescription)")
        }
    }
}
