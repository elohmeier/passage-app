import CryptoKit
import Foundation
import NIOSSH
import Security

/// A client key for git over SSH.
public enum SSHKey: Sendable, Equatable, Codable {
    /// ecdsa-sha2-nistp256 in the Secure Enclave. The blob only works on this device.
    case secureEnclaveP256(dataRepresentation: Data)
    /// ssh-ed25519, in software (for hosts that don't accept ECDSA keys).
    case ed25519(rawRepresentation: Data)

    /// Generates a Secure Enclave key. It's usable without user presence, so syncing doesn't
    /// prompt, but it can never leave the device.
    public static func generateSecureEnclave() throws -> SSHKey {
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error) else {
            throw error!.takeRetainedValue()
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
        return .secureEnclaveP256(dataRepresentation: key.dataRepresentation)
    }

    public static func generateEd25519() -> SSHKey {
        .ed25519(rawRepresentation: Curve25519.Signing.PrivateKey().rawRepresentation)
    }

    func privateKey() throws -> NIOSSHPrivateKey {
        switch self {
        case .secureEnclaveP256(let data):
            NIOSSHPrivateKey(secureEnclaveP256Key: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data))
        case .ed25519(let raw):
            NIOSSHPrivateKey(ed25519Key: try Curve25519.Signing.PrivateKey(rawRepresentation: raw))
        }
    }

    /// The public key in `authorized_keys` format, e.g. `ecdsa-sha2-nistp256 AAAA… comment`.
    public func publicKeyLine(comment: String) throws -> String {
        let line = String(openSSHPublicKey: try privateKey().publicKey)
        return comment.isEmpty ? line : "\(line) \(comment)"
    }
}

/// A host key as shown to the user.
public struct HostKey: Sendable, Equatable, Codable, Hashable {
    /// `host` or `[host]:port`, as in OpenSSH's known_hosts.
    public let host: String
    /// `ssh-ed25519 AAAA…`
    public let key: String

    public init(host: String, key: String) {
        self.host = host
        self.key = key
    }

    init(host: String, key: NIOSSHPublicKey) {
        self.init(host: host, key: String(openSSHPublicKey: key))
    }

    /// `SHA256:…`, as printed by `ssh-keygen -lf`.
    public var fingerprint: String {
        let parts = key.split(separator: " ")
        guard parts.count >= 2, let blob = Data(base64Encoded: String(parts[1])) else { return "invalid key" }
        let digest = Data(SHA256.hash(data: blob)).base64EncodedString()
        return "SHA256:" + digest.trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    public var algorithm: String { key.split(separator: " ").first.map(String.init) ?? "" }
}

/// Trusted SSH host keys.
public struct KnownHosts: Sendable, Equatable, Codable {
    public private(set) var keys: Set<HostKey>

    public init(_ keys: Set<HostKey> = []) {
        self.keys = keys
    }

    /// GitHub's published host keys, from https://api.github.com/meta (`ssh_keys`), retrieved
    /// 2026-11-08. Pinned so the first connection to GitHub doesn't rely on trust-on-first-use.
    public static let pinned: Set<HostKey> = [
        HostKey(host: "github.com", key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"),
        HostKey(
            host: "github.com",
            key: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg="),
    ]

    public enum Status: Equatable, Sendable {
        case trusted
        /// Never seen this host.
        case unknown
        /// We know other keys for this host: possibly an attack, or a re-keyed server.
        case mismatch
    }

    public func status(of key: HostKey) -> Status {
        let all = keys.union(Self.pinned)
        if all.contains(key) { return .trusted }
        return all.contains { $0.host == key.host } ? .mismatch : .unknown
    }

    public mutating func trust(_ key: HostKey) {
        keys.insert(key)
    }

    public mutating func remove(_ key: HostKey) {
        keys.remove(key)
    }
}
