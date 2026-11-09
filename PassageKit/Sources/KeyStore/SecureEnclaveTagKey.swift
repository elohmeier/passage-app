import AgeCrypto
import CryptoKit
import Foundation
import LocalAuthentication

/// A P-256 + ML-KEM-768 key pair in the Secure Enclave, used as an age tag identity.
///
/// The private keys never leave the Secure Enclave. `dataRepresentation`s are opaque blobs that
/// only this device's Secure Enclave can use, and they carry their access control with them.
public struct SecureEnclaveTagKey: TagPrivateKey {
    let p256: SecureEnclave.P256.KeyAgreement.PrivateKey
    let mlkem: SecureEnclave.MLKEM768.PrivateKey

    /// Generates a new key pair. Doesn't prompt; the protection applies to later use.
    public init(protection: KeyProtection) throws(KeyStoreError) {
        guard SecureEnclave.isAvailable else { throw .secureEnclaveUnavailable }
        let ac = try protection.secureEnclaveAccessControl()
        do {
            p256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
            mlkem = try SecureEnclave.MLKEM768.PrivateKey(accessControl: ac)
        } catch {
            throw .accessControl("Secure Enclave key generation failed: \(error.localizedDescription)")
        }
    }

    /// Restores a key. Operations reuse `context` if it has already been authenticated.
    public init(p256Data: Data, mlkemData: Data, context: LAContext?) throws(KeyStoreError) {
        do {
            p256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: p256Data, authenticationContext: context)
            mlkem = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: mlkemData, authenticationContext: context)
        } catch {
            throw .corrupted("Secure Enclave key can't be restored: \(error.localizedDescription)")
        }
    }

    public var p256DataRepresentation: Data { p256.dataRepresentation }
    public var mlkemDataRepresentation: Data { mlkem.dataRepresentation }

    public var p256PublicKey: P256.KeyAgreement.PublicKey { p256.publicKey }
    public var mlkemPublicKey: MLKEM768.PublicKey? { mlkem.publicKey }

    public func p256SharedSecret(with share: P256.KeyAgreement.PublicKey) throws(AgeError) -> Data {
        do {
            return try p256.sharedSecretFromKeyAgreement(with: share).withUnsafeBytes { Data($0) }
        } catch {
            throw .identityUnavailable(Self.describe(error))
        }
    }

    public func mlkemDecapsulate(_ ciphertext: Data) throws(AgeError) -> Data {
        do {
            return try mlkem.decapsulate(ciphertext).withUnsafeBytes { Data($0) }
        } catch {
            throw .identityUnavailable(Self.describe(error))
        }
    }

    static func describe(_ error: any Error) -> String {
        if let la = error as? LAError, la.code == .userCancel || la.code == .appCancel || la.code == .systemCancel {
            return "Authentication was cancelled."
        }
        return "The Secure Enclave key couldn't be used: \(error.localizedDescription)"
    }
}
