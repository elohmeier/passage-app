import AgeCrypto
import Foundation
import KeyStore
import LocalAuthentication
import Observation

enum AppConfig {
    static let keychainService = "de.nerdworks.passage"
    /// Team ID prefix + shared group, see Config/Passage.entitlements.
    static let keychainAccessGroup = "D7DW22G9T5.de.nerdworks.passage.shared"
    static let appGroup = "group.de.nerdworks.passage"
    /// The "Passage for iOS" GitHub App (public values; there is no client secret).
    /// Nil until the app is registered: "Connect GitHub" is hidden.
    static var gitHubClientID: String? {
        #if DEBUG
            if let id = UserDefaults.standard.string(forKey: "PassageGitHubClientID") { return id }
        #endif
        return nil
    }

    static var gitHubAppSlug: String? {
        #if DEBUG
            if let slug = UserDefaults.standard.string(forKey: "PassageGitHubSlug") { return slug }
        #endif
        return nil
    }
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

    func decrypt(_ data: Data) async throws -> Data {
        try await identityStore.decrypt(data, sessions: sessions, reason: String(localized: "Unlock your keys to decrypt"))
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
