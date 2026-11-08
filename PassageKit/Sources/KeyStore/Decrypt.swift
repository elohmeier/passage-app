import AgeCrypto
import Foundation

extension StoredIdentity {
    /// Stanza types this identity can unwrap. Used to skip authentication for files that
    /// aren't encrypted to any of our identities.
    var stanzaTypes: Set<String> {
        switch kind {
        case .secureEnclave, .simulator: ["p256tag", "mlkem768p256tag", "piv-p256"]
        case .imported: recipients.contains { $0.hasPrefix("age1pq1") } ? ["mlkem768x25519"] : ["X25519"]
        }
    }
}

extension IdentityStore {
    /// Decrypts with the stored identities, authenticating through `sessions` first.
    ///
    /// Only identities that could match one of the file's stanzas are unlocked, so a file
    /// that isn't for us fails with `AgeError.noIdentityMatch` without a Face ID prompt.
    @concurrent
    public func decrypt(_ ciphertext: Data, sessions: UnlockSessionManager, reason: String) async throws -> Data {
        let header = try Age.header(of: ciphertext)
        let present = Set(header.stanzas.map(\.type))
        let candidates = try list().filter { !$0.stanzaTypes.isDisjoint(with: present) }
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
