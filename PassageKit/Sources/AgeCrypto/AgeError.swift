import Foundation

public enum AgeError: Error, Equatable, Sendable {
    /// The ASCII armor is malformed.
    case armor(String)
    /// The header could not be parsed, or a stanza addressed to one of our identities is malformed.
    case header(String)
    /// None of the identities could unwrap any recipient stanza.
    case noIdentityMatch(stanzaTypes: [String])
    /// A file key was unwrapped, but the header MAC doesn't match: the header was tampered with.
    case headerMAC
    /// The encrypted payload is truncated, corrupted, or tampered with.
    case payload(String)
    /// A recipient, identity or other encoded value could not be parsed.
    case invalidEncoding(String)
    /// The recipients can't be combined in one file (for example post-quantum and classic).
    case incompatibleRecipients(String)
    case noRecipients
    /// A hardware or user-mediated identity operation failed (cancelled prompt, missing key, …).
    case identityUnavailable(String)

    /// Returned by identities for stanzas that are not addressed to them. Never escapes `Age.decrypt`.
    case incorrectIdentity
}

extension AgeError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .armor(let m): "Invalid armor: \(m)"
        case .header(let m): "Invalid age header: \(m)"
        case .noIdentityMatch(let types):
            "No identity matched any of the recipients (\(types.joined(separator: ", ")))"
        case .headerMAC: "Bad header MAC: the file was modified or corrupted"
        case .payload(let m): "Invalid payload: \(m)"
        case .invalidEncoding(let m): m
        case .incompatibleRecipients(let m): m
        case .noRecipients: "No recipients specified"
        case .identityUnavailable(let m): m
        case .incorrectIdentity: "Identity did not match"
        }
    }
}
