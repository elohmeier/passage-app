import AgeCrypto
import CoreGraphics
import CryptoKit
import Foundation
import LocalAuthentication
import Synchronization
import Testing

@testable import KeyStore

let message = Data("hunter2\nusername: alice\n".utf8)

/// Keys that require a passcode can't be created while the Mac's screen is locked
/// (errSecInteractionNotAllowed), just like on a locked iPhone.
let screenUnlocked: Bool = {
    guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return true }
    return session["CGSSessionScreenIsLocked"] as? Bool != true
}()

/// Uses the real Secure Enclave (Apple-silicon Macs). `.unprotected` protection avoids Touch ID
/// prompts; access control itself is only verifiable on a device.
@Suite(.enabled(if: SecureEnclave.isAvailable, "needs a Secure Enclave"))
struct SecureEnclaveIdentityTests {
    let secrets = InMemorySecretStore()
    var store: IdentityStore { IdentityStore(store: secrets) }

    @Test func deviceIdentityDecryptsBothRecipientTypes() throws {
        let created = try store.createDeviceIdentity(name: "iPhone", protection: .unprotected)
        #expect(created.kind == .secureEnclave)
        #expect(created.recipients.count == 2)
        #expect(created.recipients[0].hasPrefix("age1tag1"))
        #expect(created.recipients[1].hasPrefix("age1tagpq1"))
        #expect(try store.list() == [created])

        let identities = try store.unlock(context: nil)
        for recipient in created.recipients {
            let ct = try Age.encrypt(message, to: [RecipientParser.parse(recipient)])
            #expect(try Age.decrypt(ct, identities: identities) == message)
        }
    }

    @Test(.enabled(if: screenUnlocked, "needs an unlocked screen"))
    func biometryProtectedKeyCanBeCreated() throws {
        // Creation doesn't prompt; using the key would.
        let key = try SecureEnclaveTagKey(protection: .biometryCurrentSet)
        #expect(key.mlkemPublicKey != nil)
    }

    @Test func importedIdentitiesAreWrappedBySecureEnclave() throws {
        let x = X25519Identity()
        let pq = try HybridIdentity()
        let imported = try store.importIdentities(
            "# from desktop\n\(x.encoded)\n\n\(pq.encoded)\n", name: "Desktop", protection: .unprotected)
        #expect(imported.map(\.name) == ["Desktop 1", "Desktop 2"])
        #expect(imported.map(\.recipients) == [[x.recipient.encoded], [pq.recipient.encoded]])

        // Nothing in the store is the plaintext secret key.
        for key in secrets.keys {
            let data = try #require(try secrets.get(key, context: nil))
            #expect(!String(decoding: data, as: UTF8.self).contains("AGE-SECRET-KEY"), "\(key) leaks the secret")
        }

        let identities = try store.unlock(context: nil)
        #expect(try Age.decrypt(Age.encrypt(message, to: [x.recipient]), identities: identities) == message)
        #expect(try Age.decrypt(Age.encrypt(message, to: [pq.recipient]), identities: identities) == message)
    }

    @Test func invalidImportStoresNothing() throws {
        let good = X25519Identity().encoded
        #expect(throws: KeyStoreError.self) {
            try store.importIdentities("\(good)\nAGE-PLUGIN-YUBIKEY-1QQQQQQ\n", name: "x", protection: .unprotected)
        }
        #expect(secrets.keys.isEmpty)
    }

    @Test func deleteRemovesKeyMaterial() throws {
        let a = try store.createDeviceIdentity(name: "a", protection: .unprotected)
        let b = try store.importIdentities(X25519Identity().encoded, name: "b", protection: .unprotected)[0]
        try store.delete(b.id)
        #expect(try store.list() == [a])
        #expect(secrets.keys.allSatisfy { $0 == "index" || $0.hasPrefix(a.id.uuidString) })
        try store.delete(a.id)
        #expect(secrets.keys == ["index"])
    }

    @Test func renamePersists() throws {
        let a = try store.createDeviceIdentity(name: "a", protection: .unprotected)
        try store.rename(a.id, to: "Enno's iPhone")
        #expect(try store.list().map(\.name) == ["Enno's iPhone"])
    }
}

@Suite struct RecommendedRecipientTests {
    let device = StoredIdentity(
        id: UUID(), name: "iPhone", kind: .secureEnclave, protection: .biometryCurrentSet, createdAt: .now,
        recipients: ["age1tag1classic", "age1tagpq1pq"])

    @Test func classicStoreGetsClassicRecipient() {
        #expect(device.recommendedRecipient(alongside: [X25519Identity().recipient]) == "age1tag1classic")
    }

    @Test func postQuantumStoreGetsPostQuantumRecipient() throws {
        #expect(device.recommendedRecipient(alongside: [try HybridIdentity().recipient]) == "age1tagpq1pq")
    }

    @Test func emptyStoreDefaultsToPostQuantum() {
        #expect(device.recommendedRecipient(alongside: []) == "age1tagpq1pq")
    }
}

final class FakeAuthenticator: Authenticator {
    let calls = Mutex<[LAPolicy]>([])
    let result: KeyStoreError?

    init(failingWith result: KeyStoreError? = nil) { self.result = result }

    func evaluate(_ context: LAContext, policy: LAPolicy, reason: String) async throws(KeyStoreError) {
        calls.withLock { $0.append(policy) }
        if let result { throw result }
    }

    var count: Int { calls.withLock { $0.count } }
}

final class FakeClock: Sendable {
    let time = Mutex(Date(timeIntervalSince1970: 1_000_000))
    func advance(_ seconds: TimeInterval) { time.withLock { $0 += seconds } }
    var now: @Sendable () -> Date { { self.time.withLock { $0 } } }
}

@Suite struct UnlockSessionTests {
    let auth = FakeAuthenticator()
    let clock = FakeClock()

    func manager(_ policy: UnlockPolicy) -> UnlockSessionManager {
        UnlockSessionManager(policy: policy, authenticator: auth, now: clock.now)
    }

    @Test func unprotectedKeysNeedNoPrompt() async throws {
        let m = manager(.everyTime)
        #expect(try await m.context(for: [.unprotected], reason: "test") == nil)
        #expect(auth.count == 0)
    }

    @Test func reuseWithinWindow() async throws {
        let m = manager(.reuse(seconds: 60))
        let first = try await m.context(for: [.biometryCurrentSet], reason: "test")
        clock.advance(59)
        let second = try await m.context(for: [.biometryCurrentSet], reason: "test")
        #expect(first === second)
        #expect(auth.count == 1)
        #expect(m.isUnlocked)

        clock.advance(2)
        #expect(!m.isUnlocked)
        let third = try await m.context(for: [.biometryCurrentSet], reason: "test")
        #expect(third !== first)
        #expect(auth.count == 2)
    }

    @Test func everyTimePromptsEveryTime() async throws {
        let m = manager(.everyTime)
        _ = try await m.context(for: [.userPresence], reason: "test")
        _ = try await m.context(for: [.userPresence], reason: "test")
        #expect(auth.count == 2)
        #expect(!m.isUnlocked)
    }

    @Test func lockForgetsAuthentication() async throws {
        let m = manager(.untilBackground)
        _ = try await m.context(for: [.userPresence], reason: "test")
        clock.advance(3600)
        #expect(m.isUnlocked)
        m.lock()
        #expect(!m.isUnlocked)
        _ = try await m.context(for: [.userPresence], reason: "test")
        #expect(auth.count == 2)
    }

    @Test func biometryRequiredIfAnyKeyNeedsIt() async throws {
        let m = manager(.untilBackground)
        _ = try await m.context(for: [.userPresence, .biometryCurrentSet], reason: "test")
        #expect(auth.calls.withLock { $0 } == [.deviceOwnerAuthenticationWithBiometrics])
        // A biometric session also satisfies passcode-or-biometry keys…
        _ = try await m.context(for: [.userPresence], reason: "test")
        #expect(auth.count == 1)
    }

    @Test func passcodeSessionDoesNotSatisfyBiometryOnlyKeys() async throws {
        let m = manager(.untilBackground)
        _ = try await m.context(for: [.userPresence], reason: "test")
        _ = try await m.context(for: [.biometryCurrentSet], reason: "test")
        #expect(auth.calls.withLock { $0 } == [.deviceOwnerAuthentication, .deviceOwnerAuthenticationWithBiometrics])
    }

    @Test func cancellationPropagates() async {
        let m = UnlockSessionManager(policy: .untilBackground, authenticator: FakeAuthenticator(failingWith: .cancelled))
        await #expect(throws: KeyStoreError.cancelled) {
            _ = try await m.context(for: [.userPresence], reason: "test")
        }
        #expect(!m.isUnlocked)
    }
}

@Suite(.enabled(if: SecureEnclave.isAvailable, "needs a Secure Enclave"))
struct DecryptTests {
    let secrets = InMemorySecretStore()
    let auth = FakeAuthenticator()

    @Test(.enabled(if: screenUnlocked, "needs an unlocked screen"))
    func promptsOnlyForMatchingIdentities() async throws {
        let store = IdentityStore(store: secrets)
        _ = try store.createDeviceIdentity(name: "iPhone", protection: .userPresence)
        // userPresence keys would prompt for real, so only exercise the paths that don't reach the key.
        let sessions = UnlockSessionManager(policy: .everyTime, authenticator: auth)

        let foreign = try Age.encrypt(message, to: [X25519Identity().recipient])
        await #expect(throws: AgeError.noIdentityMatch(stanzaTypes: ["X25519"])) {
            try await store.decrypt(foreign, sessions: sessions, reason: "test")
        }
        #expect(auth.count == 0, "no prompt for a file we can't read")
    }

    @Test func decryptsWithUnprotectedKeys() async throws {
        let store = IdentityStore(store: secrets)
        let device = try store.createDeviceIdentity(name: "iPhone", protection: .unprotected)
        let x = X25519Identity()
        _ = try store.importIdentities(x.encoded, name: "Desktop", protection: .unprotected)
        let sessions = UnlockSessionManager(policy: .everyTime, authenticator: auth)

        let toDevice = try Age.encrypt(message, to: [RecipientParser.parse(device.recipients[1])])
        #expect(try await store.decrypt(toDevice, sessions: sessions, reason: "test") == message)
        let toImported = try Age.encrypt(message, to: [x.recipient])
        #expect(try await store.decrypt(toImported, sessions: sessions, reason: "test") == message)
        #expect(auth.count == 0)
    }
}

/// The YubiKey path, with a software P-256 key standing in for the card's PIV slot.
@Suite(.enabled(if: SecureEnclave.isAvailable, "needs a Secure Enclave"))
struct YubiKeyTests {
    let secrets = InMemorySecretStore()
    let card = P256.KeyAgreement.PrivateKey()
    final class Counter: Sendable { let value = Mutex(0) }
    let counter = Counter()

    var hardware: HardwareKeyAgreement {
        { [card, counter] _, share in
            counter.value.withLock { $0 += 1 }
            return try card.sharedSecretFromKeyAgreement(with: share).withUnsafeBytes { Data($0) }
        }
    }

    func addCard(_ store: IdentityStore) throws -> StoredIdentity {
        try store.addYubiKey(.init(serial: 12345678, slot: 0x82, publicKey: card.publicKey.x963Representation), name: "YubiKey 5C NFC")
    }

    @Test(arguments: [0, 1])
    func decryptsBothRecipientForms(form: Int) async throws {
        let store = IdentityStore(store: secrets)
        let yubikey = try addCard(store)
        #expect(yubikey.recipients[0].hasPrefix("age1yubikey1") && yubikey.recipients[1].hasPrefix("age1tag1"))
        #expect(try addCard(store).id == yubikey.id, "adding the same slot twice is a no-op")

        let ct = try Age.encrypt(message, to: [RecipientParser.parse(yubikey.recipients[form])])
        let sessions = UnlockSessionManager(policy: .everyTime, authenticator: FakeAuthenticator())
        #expect(try await store.decrypt(ct, sessions: sessions, reason: "t", hardware: hardware) == message)
        #expect(counter.value.withLock { $0 } == 1)
    }

    @Test func prefersTheDeviceKey() async throws {
        let store = IdentityStore(store: secrets)
        let device = try store.createDeviceIdentity(name: "iPhone", protection: .unprotected)
        let yubikey = try addCard(store)
        let ct = try Age.encrypt(message, to: [RecipientParser.parse(device.recipients[0]), RecipientParser.parse(yubikey.recipients[1])])
        let sessions = UnlockSessionManager(policy: .everyTime, authenticator: FakeAuthenticator())
        #expect(try await store.decrypt(ct, sessions: sessions, reason: "t", hardware: hardware) == message)
        #expect(counter.value.withLock { $0 } == 0, "no YubiKey tap when the device key works")
    }

    @Test func notAskedForOtherFiles() async throws {
        let store = IdentityStore(store: secrets)
        _ = try addCard(store)
        let ct = try Age.encrypt(message, to: [X25519Identity().recipient])
        let sessions = UnlockSessionManager(policy: .everyTime, authenticator: FakeAuthenticator())
        await #expect(throws: AgeError.self) { try await store.decrypt(ct, sessions: sessions, reason: "t", hardware: hardware) }
        #expect(counter.value.withLock { $0 } == 0)
    }
}
