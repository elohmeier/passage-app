import CryptoKit
import Foundation

/// A WebAuthn passkey (ES256) stored as a pass entry, using KeePassXC's attribute names so
/// entries can move between KeePassXC and passage:
///
///     <empty first line>
///     username: alice
///     url: https://github.com
///     KPEX_PASSKEY_RELYING_PARTY: github.com
///     KPEX_PASSKEY_USERNAME: alice
///     KPEX_PASSKEY_CREDENTIAL_ID: <base64url>
///     KPEX_PASSKEY_USER_HANDLE: <base64url>
///     KPEX_PASSKEY_PRIVATE_KEY_PEM: |
///       -----BEGIN PRIVATE KEY-----
///       …
///     KPEX_PASSKEY_FLAG_BE: 1
///     KPEX_PASSKEY_FLAG_BS: 1
///
/// The private key is a software key (exportable, so the same passkey works on other
/// platforms), protected like any other entry: by age encryption to the folder's recipients.
public struct Passkey: Sendable, Equatable {
    public var relyingParty: String
    public var userName: String
    public var credentialID: Data
    public var userHandle: Data
    public var privateKey: P256.Signing.PrivateKey
    /// Backup eligibility / state. Synced passkeys are both.
    public var backupEligible = true
    public var backedUp = true

    /// Passage's authenticator model ID, shown by some sites as the passkey provider.
    public static let aaguid = UUID(uuidString: "5A64E0D8-8B2A-4B8C-9B6E-6E1C0F7A2F11")!

    enum Field {
        static let relyingParty = "KPEX_PASSKEY_RELYING_PARTY"
        static let userName = "KPEX_PASSKEY_USERNAME"
        static let credentialID = "KPEX_PASSKEY_CREDENTIAL_ID"
        static let userHandle = "KPEX_PASSKEY_USER_HANDLE"
        static let privateKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM"
        static let backupEligible = "KPEX_PASSKEY_FLAG_BE"
        static let backedUp = "KPEX_PASSKEY_FLAG_BS"
    }

    public init(
        relyingParty: String, userName: String, credentialID: Data, userHandle: Data, privateKey: P256.Signing.PrivateKey
    ) {
        self.relyingParty = relyingParty
        self.userName = userName
        self.credentialID = credentialID
        self.userHandle = userHandle
        self.privateKey = privateKey
    }

    /// A new passkey with a random 32-byte credential ID.
    public static func create(relyingParty: String, userName: String, userHandle: Data) -> Passkey {
        Passkey(
            relyingParty: relyingParty, userName: userName, credentialID: randomBytes(32), userHandle: userHandle,
            privateKey: P256.Signing.PrivateKey())
    }

    /// Reads a passkey from an entry; nil if it has no (valid) passkey fields.
    public init?(entry: Entry) {
        func field(_ name: String) -> String? {
            entry.fields.first { $0.key?.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
        guard let rp = field(Field.relyingParty), let id = field(Field.credentialID).flatMap(Base64URL.decode),
            let pem = field(Field.privateKey), let key = try? P256.Signing.PrivateKey(pemRepresentation: pem)
        else { return nil }
        relyingParty = rp
        userName = field(Field.userName) ?? entry.username ?? ""
        credentialID = id
        userHandle = field(Field.userHandle).flatMap(Base64URL.decode) ?? Data()
        privateKey = key
        backupEligible = field(Field.backupEligible).map { $0 == "1" || $0.lowercased() == "true" } ?? true
        backedUp = field(Field.backedUp).map { $0 == "1" || $0.lowercased() == "true" } ?? true
    }

    /// The entry text for this passkey.
    public var entryText: String {
        var draft = EntryDraft(password: "")
        draft.username = userName
        draft.url = "https://" + relyingParty
        draft.otherFields = [
            .init(key: Field.relyingParty, value: relyingParty),
            .init(key: Field.userName, value: userName),
            .init(key: Field.credentialID, value: Base64URL.encode(credentialID)),
            .init(key: Field.userHandle, value: Base64URL.encode(userHandle)),
            .init(key: Field.privateKey, value: privateKey.pemRepresentation),
            .init(key: Field.backupEligible, value: backupEligible ? "1" : "0"),
            .init(key: Field.backedUp, value: backedUp ? "1" : "0"),
        ]
        return draft.text
    }

    /// Suggested store path, e.g. `passkeys/github.com/alice`.
    public var suggestedPath: EntryPath {
        let user = userName.isEmpty ? Base64URL.encode(credentialID.prefix(6)) : userName
        let safe = user.replacingOccurrences(of: "/", with: "_")
        return EntryPath("passkeys/\(relyingParty)/\(safe)")
    }

    // MARK: WebAuthn

    enum Flag {
        static let userPresent: UInt8 = 0x01
        static let userVerified: UInt8 = 0x04
        static let backupEligible: UInt8 = 0x08
        static let backedUp: UInt8 = 0x10
        static let attestedCredentialData: UInt8 = 0x40
    }

    private var flags: UInt8 {
        Flag.userPresent | Flag.userVerified | (backupEligible ? Flag.backupEligible : 0) | (backedUp ? Flag.backedUp : 0)
    }

    /// authenticatorData for an assertion: rpIdHash ‖ flags ‖ signCount (always 0: synced
    /// passkeys can't keep a monotonic counter).
    public func assertionAuthenticatorData() -> Data {
        Data(SHA256.hash(data: Data(relyingParty.utf8))) + [flags] + Data(count: 4)
    }

    /// Signs `authenticatorData ‖ clientDataHash` (ES256, DER signature as WebAuthn expects).
    public func assertion(clientDataHash: Data) throws -> (authenticatorData: Data, signature: Data) {
        let authenticatorData = assertionAuthenticatorData()
        let signature = try privateKey.signature(for: authenticatorData + clientDataHash).derRepresentation
        return (authenticatorData, signature)
    }

    /// The attestation object for registration ("none" attestation).
    public func attestationObject() -> Data {
        var authData = Data(SHA256.hash(data: Data(relyingParty.utf8)))
        authData.append(flags | Flag.attestedCredentialData)
        authData += Data(count: 4)
        authData += withUnsafeBytes(of: Self.aaguid.uuid) { Data($0) }
        authData += [UInt8(credentialID.count >> 8), UInt8(credentialID.count & 0xFF)]
        authData += credentialID
        authData += coseKey
        // CTAP2 canonical key order: "fmt", "attStmt", "authData" (shorter keys first).
        return CBOR.map([
            (CBOR.text("fmt"), CBOR.text("none")),
            (CBOR.text("attStmt"), CBOR.map([])),
            (CBOR.text("authData"), CBOR.bytes(authData)),
        ])
    }

    /// COSE_Key for the public key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
    public var coseKey: Data {
        let point = privateKey.publicKey.x963Representation  // 0x04 ‖ x ‖ y
        return CBOR.map([
            (CBOR.int(1), CBOR.int(2)),
            (CBOR.int(3), CBOR.int(-7)),
            (CBOR.int(-1), CBOR.int(1)),
            (CBOR.int(-2), CBOR.bytes(point[1..<33])),
            (CBOR.int(-3), CBOR.bytes(point[33..<65])),
        ])
    }

    public static func == (a: Self, b: Self) -> Bool {
        a.relyingParty == b.relyingParty && a.userName == b.userName && a.credentialID == b.credentialID
            && a.userHandle == b.userHandle && a.privateKey.rawRepresentation == b.privateKey.rawRepresentation
            && a.backupEligible == b.backupEligible && a.backedUp == b.backedUp
    }

    private static func randomBytes(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<n).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }
}

/// The handful of CBOR (RFC 8949) encodings WebAuthn needs, in canonical form. Callers pass
/// map entries already in canonical order.
enum CBOR {
    static func head(_ major: UInt8, _ value: UInt64) -> Data {
        let m = major << 5
        switch value {
        case ..<24: return Data([m | UInt8(value)])
        case ..<0x100: return Data([m | 24, UInt8(value)])
        case ..<0x10000: return Data([m | 25, UInt8(value >> 8), UInt8(value & 0xFF)])
        case ..<0x1_0000_0000: return Data([m | 26] + (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt64(8 * (3 - $0))) })
        default: return Data([m | 27] + (0..<8).map { UInt8(truncatingIfNeeded: value >> UInt64(8 * (7 - $0))) })
        }
    }

    static func int(_ v: Int) -> Data { v >= 0 ? head(0, UInt64(v)) : head(1, UInt64(-1 - v)) }
    static func bytes(_ d: some DataProtocol) -> Data { head(2, UInt64(d.count)) + Data(d) }
    static func text(_ s: String) -> Data { head(3, UInt64(s.utf8.count)) + Data(s.utf8) }
    static func map(_ entries: [(Data, Data)]) -> Data { entries.reduce(head(5, UInt64(entries.count))) { $0 + $1.0 + $1.1 } }
}

/// Unpadded base64url (RFC 4648 §5), as WebAuthn and KeePassXC use.
public enum Base64URL {
    public static func encode(_ data: some DataProtocol) -> String {
        Data(data).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ string: String) -> Data? {
        var s = string.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        return Data(base64Encoded: s)
    }
}
