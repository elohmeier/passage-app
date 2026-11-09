import AgeCrypto
import Foundation
import KeyStore
import LocalAuthentication
import Observation
import PassStore

enum AppConfig {
    static let keychainService = "de.nerdworks.passage"
    /// Team ID prefix + shared group, see Config/Passage.entitlements.
    static let keychainAccessGroup = "D7DW22G9T5.de.nerdworks.passage.shared"
    static let appGroup = "group.de.nerdworks.passage"
    /// The "Passage for iOS" GitHub App, https://github.com/apps/passage-for-ios (owner
    /// elohmeier). Public values; the app has no client secret or private key.
    static let gitHubClientID: String? = "Iv23liOwqYZ8vfmPGohG"
    static let gitHubAppSlug: String? = "passage-for-ios"
}

/// The unlock policy choices offered in Settings.
enum UnlockOption: String, CaseIterable, Identifiable {
    case everyTime, oneMinute, fiveMinutes, untilBackground

    var id: Self { self }

    var policy: UnlockPolicy {
        switch self {
        case .everyTime: .everyTime
        case .oneMinute: .reuse(seconds: 60)
        case .fiveMinutes: .reuse(seconds: 300)
        case .untilBackground: .untilBackground
        }
    }

    var title: LocalizedStringResource {
        switch self {
        case .everyTime: "Every Time"
        case .oneMinute: "After 1 Minute"
        case .fiveMinutes: "After 5 Minutes"
        case .untilBackground: "When Leaving the App"
        }
    }
}

@MainActor @Observable
final class AppModel {
    let identityStore: IdentityStore
    let sessions: UnlockSessionManager
    private let defaults: UserDefaults

    private(set) var identities: [StoredIdentity] = []
    var errorMessage: String?
    /// Set by intents that open the app at a specific place.
    var pendingRoute: PendingRoute?

    /// Seconds until copied secrets are removed from the clipboard.
    var clipboardSeconds: Int {
        didSet { defaults.set(clipboardSeconds, forKey: "clipboardSeconds") }
    }

    var unlockOption: UnlockOption {
        didSet {
            defaults.set(unlockOption.rawValue, forKey: "unlockOption")
            sessions.policy = unlockOption.policy
        }
    }

    var deviceIdentity: StoredIdentity? {
        identities.first { $0.kind == .secureEnclave || $0.kind == .simulator }
    }

    init(secrets: any SecretStore, defaults: UserDefaults) {
        let option = defaults.string(forKey: "unlockOption").flatMap(UnlockOption.init) ?? .oneMinute
        identityStore = IdentityStore(store: secrets)
        sessions = UnlockSessionManager(policy: option.policy)
        unlockOption = option
        clipboardSeconds = defaults.object(forKey: "clipboardSeconds") as? Int ?? 30
        self.defaults = defaults
        reload()
    }

    static func live() -> AppModel {
        AppModel(
            secrets: KeychainSecretStore(service: AppConfig.keychainService, accessGroup: AppConfig.keychainAccessGroup),
            defaults: sharedDefaults)
    }

    static var sharedDefaults: UserDefaults { UserDefaults(suiteName: AppConfig.appGroup) ?? .standard }

    static func preview() -> AppModel {
        AppModel(secrets: InMemorySecretStore(), defaults: UserDefaults(suiteName: "preview")!)
    }

    func reload() {
        attempt { identities = try identityStore.list() }
    }

    /// Creates this device's key. Biometry-only if Face ID / Touch ID is set up, otherwise
    /// biometry or passcode, so the key is usable on devices without enrolled biometry.
    @discardableResult
    func createDeviceIdentity(name: String, protection: KeyProtection? = nil) -> StoredIdentity? {
        let protection = protection ?? (LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            ? .biometryCurrentSet : .userPresence)
        var created: StoredIdentity?
        attempt { created = try identityStore.createDeviceIdentity(name: name, protection: protection) }
        reload()
        return created
    }

    func importIdentities(_ text: String, name: String, protection: KeyProtection) -> Bool {
        let ok = attempt { _ = try identityStore.importIdentities(text, name: name, protection: protection) }
        reload()
        return ok
    }

    func rename(_ identity: StoredIdentity, to name: String) {
        attempt { try identityStore.rename(identity.id, to: name) }
        reload()
    }

    func delete(_ identity: StoredIdentity) {
        attempt { try identityStore.delete(identity.id) }
        reload()
    }

    /// The YubiKey half of decryption; set by the app (extensions can't use NFC).
    var hardwareKeyAgreement: HardwareKeyAgreement?

    func decrypt(_ data: Data) async throws -> Data {
        try await decryptVerifying(data).plaintext
    }

    /// Also tells whether the user was verified (for a passkey's UV flag).
    /// `silent`: no UI of ours is on screen (AutoFill's silent fill); see
    /// `IdentityStore.decryptVerifying(promptInKeyOperation:)`.
    func decryptVerifying(_ data: Data, silent: Bool = false) async throws -> (plaintext: Data, userVerified: Bool) {
        try await identityStore.decryptVerifying(
            data, sessions: sessions, reason: String(localized: "Unlock your keys to decrypt"), hardware: hardwareKeyAgreement,
            promptInKeyOperation: silent)
    }

    func addYubiKey(_ ref: StoredIdentity.YubiKeyRef, name: String) -> Bool {
        let ok = attempt { _ = try identityStore.addYubiKey(ref, name: name) }
        reload()
        return ok
    }

    /// Decrypts every entry once (one authentication) to learn URLs and usernames for AutoFill.
    func prepareAutoFill(store: StoreModel) async throws -> Int {
        guard let local = store.store else { return 0 }
        let identities = try await identityStore.unlockAll(sessions: sessions, reason: String(localized: "Unlock your keys to prepare AutoFill"))
        var learned = 0
        for entry in store.snapshot.entries {
            guard let data = try? await local.read(entry), let plaintext = try? Age.decrypt(data, identities: identities) else { continue }
            await AutoFillStore.learn(entry, from: Entry(String(decoding: plaintext, as: UTF8.self)))
            learned += 1
        }
        return learned
    }

    func lock() {
        sessions.lock()
    }

    @discardableResult
    private func attempt(_ body: () throws -> Void) -> Bool {
        do {
            try body()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }
}
