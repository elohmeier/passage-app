import CGit2
import Foundation

public enum GitSync {
    /// libgit2 must be initialized once per process before use.
    static let initialized: Void = {
        git_libgit2_init()
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
        case uncommittedChanges
        case network
        case other
    }

    public let kind: Kind
    public let message: String
    public let code: Int32

    public var errorDescription: String? {
        switch kind {
        case .authentication: "Authentication failed: \(message)"
        case .diverged: "Your local copy and the remote have both changed. Merging comes in a later version."
        case .uncommittedChanges: "The local copy has changes that would be overwritten."
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
