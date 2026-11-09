import Foundation
import LocalAuthentication
import Security
import Synchronization

/// Storage for key material and metadata. The real implementation is the keychain. Tests use
/// `InMemorySecretStore`, because the data protection keychain needs app entitlements.
public protocol SecretStore: Sendable {
    /// Stores `data`. With `accessControl`, reading it requires the given user authentication;
    /// without, it is readable while the device is unlocked.
    func set(_ data: Data, for key: String, accessControl: SecAccessControl?) throws(KeyStoreError)
    /// Stores `data` readable after the first unlock since boot, without user presence. Only
    /// for credentials background work needs (git sync), never for identity keys.
    func setAvailableAfterFirstUnlock(_ data: Data, for key: String) throws(KeyStoreError)
    /// Reads an item. `context` is used to satisfy access control without another prompt.
    func get(_ key: String, context: LAContext?) throws(KeyStoreError) -> Data?
    func delete(_ key: String) throws(KeyStoreError)
}

/// Generic password items in the data protection keychain, never synchronized to iCloud.
public struct KeychainSecretStore: SecretStore {
    public let service: String
    /// Shared with the extensions, e.g. `D7DW22G9T5.de.nerdworks.passage.shared`.
    public let accessGroup: String?

    public init(service: String, accessGroup: String?) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func query(_ key: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public func set(_ data: Data, for key: String, accessControl: SecAccessControl?) throws(KeyStoreError) {
        try delete(key)
        var q = query(key)
        q[kSecValueData as String] = data
        if let accessControl {
            q[kSecAttrAccessControl as String] = accessControl
        } else {
            q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw .keychain(status) }
    }

    public func setAvailableAfterFirstUnlock(_ data: Data, for key: String) throws(KeyStoreError) {
        try delete(key)
        var q = query(key)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw .keychain(status) }
    }

    public func get(_ key: String, context: LAContext?) throws(KeyStoreError) -> Data? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context { q[kSecUseAuthenticationContext as String] = context }
        var result: CFTypeRef?
        switch SecItemCopyMatching(q as CFDictionary, &result) {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        case errSecUserCanceled: throw .cancelled
        case errSecAuthFailed: throw .authenticationFailed("keychain item")
        case let status: throw .keychain(status)
        }
    }

    public func delete(_ key: String) throws(KeyStoreError) {
        let status = SecItemDelete(query(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw .keychain(status) }
    }
}

/// For tests and SwiftUI previews. Ignores access control.
public final class InMemorySecretStore: SecretStore {
    private let items = Mutex<[String: Data]>([:])

    public init() {}

    public func set(_ data: Data, for key: String, accessControl: SecAccessControl?) throws(KeyStoreError) {
        items.withLock { $0[key] = data }
    }

    public func get(_ key: String, context: LAContext?) throws(KeyStoreError) -> Data? {
        items.withLock { $0[key] }
    }

    public func setAvailableAfterFirstUnlock(_ data: Data, for key: String) throws(KeyStoreError) {
        items.withLock { $0[key] = data }
    }

    public func delete(_ key: String) throws(KeyStoreError) {
        _ = items.withLock { $0.removeValue(forKey: key) }
    }

    public var keys: [String] { items.withLock { Array($0.keys) } }
}
