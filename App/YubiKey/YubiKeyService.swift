import CryptoKit
import Foundation
import KeyStore
import Observation
import YubiKit

/// Talks to YubiKeys over NFC (or USB-C when one is plugged in): reads PIV slot keys and
/// performs the ECDH for decryption. The private key never leaves the YubiKey.
@MainActor @Observable
final class YubiKeyService {
    static let shared = YubiKeyService()

    /// A pending PIN prompt, shown as an alert by the app. Asked *before* tapping, because
    /// the NFC sheet covers the app while the YubiKey is being read.
    struct PINRequest: Identifiable {
        let id = UUID()
        let message: String
        let continuation: CheckedContinuation<String?, Never>
    }

    var pinRequest: PINRequest?
    /// Kept for the unlock session only; cleared when the app locks.
    private var cachedPIN: String?

    struct SlotKey: Identifiable, Hashable {
        let slot: UInt8
        let publicKey: Data
        let needsPIN: Bool
        var id: UInt8 { slot }
    }

    enum Failure: Error, LocalizedError {
        case cancelled
        case wrongYubiKey(expected: UInt32, found: UInt32)
        case pinBlocked
        case noP256Keys

        var errorDescription: String? {
            switch self {
            case .cancelled: String(localized: "Cancelled.")
            case .wrongYubiKey(let expected, let found):
                String(localized: "This is YubiKey \(found), but the key is on YubiKey \(expected).")
            case .pinBlocked: String(localized: "The YubiKey's PIN is blocked. Unblock it with the PUK on a computer.")
            case .noP256Keys:
                String(localized: "No P-256 keys found in the YubiKey's retired PIV slots. Create one on a computer with age-plugin-yubikey.")
            }
        }
    }

    func forgetPIN() {
        cachedPIN = nil
    }

    // MARK: Reading keys

    /// Reads the serial number and every P-256 key in the retired slots (82–95), where
    /// age-plugin-yubikey creates its keys.
    func scan() async throws -> (serial: UInt32, keys: [SlotKey]) {
        let connection = try await connect(message: String(localized: "Hold your YubiKey near the top of your iPhone."))
        do throws(any Error) {
            let session = try await PIVSession.makeSession(connection: connection)
            let serial = UInt32(try await session.getSerialNumber())
            var keys: [SlotKey] = []
            for raw in UInt8(0x82)...UInt8(0x95) {
                guard let slot = PIV.Slot(rawValue: raw), let metadata = try? await session.getMetadata(in: slot),
                    case .ec(let key) = metadata.publicKey, key.curve == .secp256r1
                else { continue }
                keys.append(SlotKey(slot: raw, publicKey: key.x963, needsPIN: metadata.pinPolicy != .never))
            }
            await close(connection, message: String(localized: "Found \(keys.count) keys."))
            guard !keys.isEmpty else { throw Failure.noP256Keys }
            return (serial, keys)
        } catch let error as Failure {
            throw error
        } catch {
            await close(connection, error: error)
            throw error
        }
    }

    // MARK: Decrypting

    /// The ECDH for `share` with the identity's slot: the hardware half of decryption.
    func keyAgreement(for identity: StoredIdentity, share: P256.KeyAgreement.PublicKey) async throws -> Data {
        guard let ref = identity.yubiKey, let slot = PIV.Slot(rawValue: ref.slot),
            let peer = EC.PublicKey(x963: share.x963Representation, curve: .secp256r1)
        else { throw Failure.noP256Keys }

        var pin: String?
        if ref.needsPIN {
            pin = try await requestPIN(String(localized: "Enter the PIN of \(identity.name)."))
        }
        while true {
            let connection = try await connect(message: String(localized: "Hold \(identity.name) near the top of your iPhone."))
            do throws(any Error) {
                let session = try await PIVSession.makeSession(connection: connection)
                let serial = UInt32(try await session.getSerialNumber())
                guard serial == ref.serial else { throw Failure.wrongYubiKey(expected: ref.serial, found: serial) }
                if let current = pin {
                    switch try await session.verifyPin(current) {
                    case .success:
                        cachedPIN = current
                    case .fail(let retries):
                        cachedPIN = nil
                        await close(connection, error: nil)
                        pin = try await requestPIN(String(localized: "Wrong PIN. \(retries) tries left."), useCache: false)
                        continue
                    case .pinLocked:
                        throw Failure.pinBlocked
                    }
                }
                let secret = try await session.deriveSharedSecret(in: slot, with: peer)
                await close(connection, message: String(localized: "Done."))
                return secret
            } catch {
                await close(connection, error: error)
                throw error
            }
        }
    }

    private func requestPIN(_ message: String, useCache: Bool = true) async throws -> String {
        if useCache, let cachedPIN { return cachedPIN }
        let pin = await withCheckedContinuation { continuation in
            pinRequest = PINRequest(message: message, continuation: continuation)
        }
        guard let pin, !pin.isEmpty else { throw Failure.cancelled }
        return pin
    }

    // MARK: Connections

    /// USB-C if a YubiKey is plugged in, otherwise NFC.
    private func connect(message: String) async throws -> SmartCardConnection {
        if let wired = try? await withTimeout(.milliseconds(400), { try await WiredSmartCardConnection.makeConnection() }) {
            return wired
        }
        return try await NFCSmartCardConnection.makeConnection(alertMessage: message)
    }

    private func close(_ connection: SmartCardConnection, message: String? = nil, error: (any Error)? = nil) async {
        if let nfc = connection as? NFCSmartCardConnection {
            if let error {
                await nfc.close(error: error)
            } else {
                await nfc.close(message: message)
            }
        } else {
            await connection.close(error: error)
        }
    }
}

/// Runs `body`, giving up after `timeout`.
private func withTimeout<T: Sendable>(_ timeout: Duration, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw CancellationError()
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}
