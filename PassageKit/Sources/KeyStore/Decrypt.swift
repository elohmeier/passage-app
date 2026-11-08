import AgeCrypto
import CryptoKit
import Foundation

extension StoredIdentity {
    /// Stanza types this identity can unwrap. Used to skip authentication for files that
    /// aren't encrypted to any of our identities.
    var stanzaTypes: Set<String> {
        switch kind {
        case .secureEnclave, .simulator: ["p256tag", "mlkem768p256tag", "piv-p256"]
        case .yubikey: ["p256tag", "piv-p256"]
        case .imported: recipients.contains { $0.hasPrefix("age1pq1") } ? ["mlkem768x25519"] : ["X25519"]
        }
    }
}

/// Performs the P-256 key agreement for a hardware-backed identity (a YubiKey): returns the
/// x-coordinate of the shared point for `share`. May show UI (NFC sheet, PIN prompt).
public typealias HardwareKeyAgreement = @Sendable (StoredIdentity, P256.KeyAgreement.PublicKey) async throws -> Data

extension IdentityStore {
    /// Decrypts with the stored identities, authenticating through `sessions` first.
    ///
    /// Only identities that could match one of the file's stanzas are unlocked, so a file
    /// that isn't for us fails with `AgeError.noIdentityMatch` without a Face ID prompt.
    /// Hardware identities (YubiKeys) are only used, via `hardware`, when no other identity can
    /// open the file, judged from stanza tags, so a YubiKey tap is never asked for needlessly.
    @concurrent
    public func decrypt(
        _ ciphertext: Data, sessions: UnlockSessionManager, reason: String, hardware: HardwareKeyAgreement? = nil
    ) async throws -> Data {
        let header = try Age.header(of: ciphertext)
        let present = Set(header.stanzas.map(\.type))
        let all = try list()

        // A device key that the header is addressed to wins outright.
        let deviceAddressed = all.contains { identity in
            (identity.kind == .secureEnclave || identity.kind == .simulator)
                && identity.recipients.compactMap { try? TagRecipient($0) }.first?.canDecrypt(header) == true
        }
        if !deviceAddressed, let hardware {
            for identity in all where identity.kind == .yubikey {
                guard let ref = identity.yubiKey, let key = try? P256.KeyAgreement.PublicKey(x963Representation: ref.publicKey) else {
                    continue
                }
                let recipient = TagRecipient(kind: .p256tag, p256PublicKey: key)
                guard let share = header.stanzas.lazy.compactMap(recipient.share(in:)).first else { continue }
                let secret = try await hardware(identity, share)
                let tagKey = PrecomputedTagKey(publicKey: key, secrets: [share.x963Representation: secret])
                return try Age.decrypt(ciphertext, identities: [TagIdentity(key: tagKey)])
            }
        }

        let candidates = all.filter { $0.kind != .yubikey && !$0.stanzaTypes.isDisjoint(with: present) }
        guard !candidates.isEmpty else { throw AgeError.noIdentityMatch(stanzaTypes: header.stanzas.map(\.type)) }

        let context = try await sessions.context(for: candidates.map(\.protection), reason: reason)
        let identities = try unlock(candidates, context: context)
        return try Age.decrypt(ciphertext, identities: identities)
    }
}

extension IdentityStore {
    /// Authenticates once and returns every identity, ready for many decryptions (for example
    /// indexing the whole store). The returned identities keep the authenticated context.
    @concurrent
    public func unlockAll(sessions: UnlockSessionManager, reason: String) async throws -> [any AgeIdentity] {
        let all = try list()
        let context = try await sessions.context(for: all.map(\.protection), reason: reason)
        return try unlock(all, context: context)
    }
}
