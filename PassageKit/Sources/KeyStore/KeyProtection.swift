import Foundation
import LocalAuthentication
import Security

/// How a stored key is protected when it is used.
public enum KeyProtection: String, Codable, Sendable, CaseIterable {
    /// Face ID / Touch ID with the current enrollment. Adding a face or finger invalidates the
    /// key, so someone who learns the passcode can't enroll themselves and use it.
    case biometryCurrentSet
    /// Face ID / Touch ID, or the device passcode as a fallback.
    case userPresence
    /// No user authentication. Only for tests and the demo store.
    case unprotected

    /// Flags for a key that lives in the Secure Enclave.
    func secureEnclaveAccessControl() throws(KeyStoreError) -> SecAccessControl {
        try make(flags: userFlags.union(.privateKeyUsage))
    }

    /// Flags for a keychain item, used when there is no Secure Enclave (Simulator).
    func keychainAccessControl() throws(KeyStoreError) -> SecAccessControl {
        try make(flags: userFlags)
    }

    /// The LocalAuthentication policy that satisfies this protection, so one evaluation can
    /// unlock several keys.
    var policy: LAPolicy? {
        switch self {
        case .biometryCurrentSet: .deviceOwnerAuthenticationWithBiometrics
        case .userPresence: .deviceOwnerAuthentication
        case .unprotected: nil
        }
    }

    private var userFlags: SecAccessControlCreateFlags {
        switch self {
        case .biometryCurrentSet: .biometryCurrentSet
        case .userPresence: .userPresence
        case .unprotected: []
        }
    }

    private func make(flags: SecAccessControlCreateFlags) throws(KeyStoreError) -> SecAccessControl {
        // Keys requiring user presence also disappear if the device passcode is removed.
        let accessibility = self == .unprotected ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, accessibility, flags, &error) else {
            throw .accessControl(error?.takeRetainedValue().localizedDescription ?? "unknown error")
        }
        return ac
    }
}

public enum KeyStoreError: Error, Equatable, Sendable, LocalizedError {
    case secureEnclaveUnavailable
    case accessControl(String)
    case keychain(OSStatus)
    case notFound
    case corrupted(String)
    case cancelled
    case authenticationFailed(String)
    case invalidIdentity(String)

    public var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable: "This device has no Secure Enclave."
        case .accessControl(let m): "Couldn't set up key protection: \(m)"
        case .keychain(let status):
            "Keychain error \(status): \(SecCopyErrorMessageString(status, nil) as String? ?? "unknown")"
        case .notFound: "The key was not found in the keychain."
        case .corrupted(let m): "Stored key data is corrupted: \(m)"
        case .cancelled: "Authentication was cancelled."
        case .authenticationFailed(let m): "Authentication failed: \(m)"
        case .invalidIdentity(let m): m
        }
    }
}
