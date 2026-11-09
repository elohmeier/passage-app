import CGit2
import Foundation

public enum GitSync {
    /// libgit2 must be initialized once per process before use.
    static let initialized: Void = {
        git_libgit2_init()
        _ = SSHTransport.registered
    }()

    public static var libgit2Version: String {
        var major: Int32 = 0, minor: Int32 = 0, rev: Int32 = 0
        git_libgit2_version(&major, &minor, &rev)
        return "\(major).\(minor).\(rev)"
    }
}

public struct GitError: Error, LocalizedError, Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case authentication
        case notFound
        case diverged
        /// The server refused the push, usually because it has new commits.
        case pushRejected
        case uncommittedChanges
        case network
        /// First connection to an SSH host: show the fingerprint and ask the user.
        case unknownHostKey(HostKey)
        /// The host presented a different key than the one we trust.
        case hostKeyChanged(HostKey)
        /// Both sides changed a `.age-recipients`; who can read the store must not be decided
        /// automatically. Resolve on a computer.
        case recipientsConflict
        case other
    }

    public let kind: Kind
    public let message: String
    public let code: Int32

    /// Worth retrying automatically: the network dropped or wasn't up yet.
    public var isTransient: Bool { kind == .network }

    public var errorDescription: String? {
        switch kind {
        case .authentication: "Authentication failed: \(message)"
        case .diverged: "Your local copy and the remote have both changed. Merging comes in a later version."
        case .uncommittedChanges: "The local copy has changes that would be overwritten."
        case .recipientsConflict: "This device and the remote both changed \(message), which decides who can read new entries. Review it, then sync keeping the remote's version (this device's is saved as a conflict copy)."
        case .pushRejected: "The server rejected the push: \(message)"
        case .network: "Couldn't reach the server. \(message)"
        case .unknownHostKey(let key): "The authenticity of \(key.host) can't be established. Its \(key.algorithm) key fingerprint is \(key.fingerprint)."
        case .hostKeyChanged(let key):
            "The host key of \(key.host) has changed (now \(key.fingerprint)). Someone could be intercepting the connection, or the server was re-keyed."
        default: message
        }
    }

    init(kind: Kind, message: String, code: Int32 = -1) {
        self.kind = kind
        self.message = message
        self.code = code
    }

    /// Builds an error from libgit2's thread-local last error.
    static func last(_ code: Int32, kind: Kind? = nil) -> GitError {
        let err = git_error_last()
        let message = err.flatMap { $0.pointee.message.map { String(cString: $0) } } ?? "libgit2 error \(code)"
        let klass = err?.pointee.klass ?? 0
        let inferred: Kind = switch (code, klass) {
        case (GIT_EAUTH.rawValue, _): .authentication
        case (GIT_ENOTFOUND.rawValue, _): .notFound
        case (GIT_ECONFLICT.rawValue, _): .uncommittedChanges
        case (_, Int32(GIT_ERROR_NET.rawValue)), (_, Int32(GIT_ERROR_HTTP.rawValue)), (_, Int32(GIT_ERROR_SSL.rawValue)): .network
        default: .other
        }
        return GitError(kind: kind ?? inferred, message: message, code: code)
    }
}

/// Throws if `code` is a libgit2 error.
@discardableResult
func check(_ code: Int32, _ kind: GitError.Kind? = nil) throws(GitError) -> Int32 {
    guard code >= 0 else { throw GitError.last(code, kind: kind) }
    return code
}
