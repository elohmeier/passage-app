import CGit2
import Foundation

/// How to authenticate to a remote.
public enum GitCredentials: Sendable, Equatable {
    case none
    /// HTTPS basic auth. For GitHub/GitLab/Gitea, the password is a personal access token.
    case userPassword(username: String, password: String)
    /// SSH public key auth. The username defaults to the one in the URL, then `git`.
    case ssh(username: String?, key: SSHKey)
}

/// Transfer progress, reported while fetching.
public struct GitProgress: Sendable, Equatable {
    public var receivedObjects: Int
    public var totalObjects: Int
    public var receivedBytes: Int

    public init(receivedObjects: Int, totalObjects: Int, receivedBytes: Int) {
        self.receivedObjects = receivedObjects
        self.totalObjects = totalObjects
        self.receivedBytes = receivedBytes
    }

    public var fraction: Double { totalObjects == 0 ? 0 : Double(receivedObjects) / Double(totalObjects) }
}

/// State shared with libgit2's C callbacks through the `payload` pointer.
final class CallbackContext {
    let credentials: GitCredentials
    let knownHosts: KnownHosts
    let progress: (@Sendable (GitProgress) -> Void)?
    var credentialAttempts = 0
    var cancelled: () -> Bool
    /// Set by the SSH transport so a failure can be reported with its real cause.
    var sshFailure: SSHFailure?
    /// Set when the server rejects a pushed ref (e.g. not a fast-forward).
    var pushRejection: String?

    init(
        credentials: GitCredentials, knownHosts: KnownHosts = KnownHosts(), progress: (@Sendable (GitProgress) -> Void)?,
        cancelled: @escaping () -> Bool = { Task.isCancelled }
    ) {
        self.credentials = credentials
        self.knownHosts = knownHosts
        self.progress = progress
        self.cancelled = cancelled
    }

    /// Turns a failed libgit2 call into a `GitError`, preferring the SSH transport's cause.
    func error(_ code: Int32) -> GitError {
        switch sshFailure {
        case .hostKey(let key, let status)?:
            GitError(kind: status == .mismatch ? .hostKeyChanged(key) : .unknownHostKey(key), message: "host key for \(key.host) is not trusted")
        case .authentication?: GitError(kind: .authentication, message: "the server rejected the SSH key")
        case .remote(let message)?: GitError(kind: .other, message: message)
        case .timeout?: GitError(kind: .network, message: "The server didn't respond in time.")
        case .connection(let detail)?: GitError(kind: .network, message: "The connection to the server was interrupted (\(detail)).")
        case nil: GitError.last(code)
        }
    }

    /// Fills `callbacks` with our C callbacks. The context must outlive the operation.
    func install(into callbacks: inout git_remote_callbacks) {
        callbacks.payload = Unmanaged.passUnretained(self).toOpaque()
        callbacks.credentials = { out, _, usernameFromURL, allowedTypes, payload in
            let ctx = Unmanaged<CallbackContext>.fromOpaque(payload!).takeUnretainedValue()
            // libgit2 retries on failure; give up after one attempt instead of looping.
            ctx.credentialAttempts += 1
            guard ctx.credentialAttempts == 1 else { return GIT_EAUTH.rawValue }
            switch ctx.credentials {
            case .userPassword(let username, let password)
            where allowedTypes & GIT_CREDENTIAL_USERPASS_PLAINTEXT.rawValue != 0:
                return git_credential_userpass_plaintext_new(out, username, password)
            default:
                // Nothing usable for this remote; GIT_PASSTHROUGH makes libgit2 report auth failure.
                _ = usernameFromURL
                return GIT_PASSTHROUGH.rawValue
            }
        }
        callbacks.push_update_reference = { _, status, payload in
            if let status {
                let ctx = Unmanaged<CallbackContext>.fromOpaque(payload!).takeUnretainedValue()
                ctx.pushRejection = String(cString: status)
            }
            return 0
        }
        callbacks.transfer_progress = { stats, payload in
            let ctx = Unmanaged<CallbackContext>.fromOpaque(payload!).takeUnretainedValue()
            if ctx.cancelled() { return GIT_EUSER.rawValue }
            if let stats, let progress = ctx.progress {
                progress(GitProgress(
                    receivedObjects: Int(stats.pointee.received_objects), totalObjects: Int(stats.pointee.total_objects),
                    receivedBytes: Int(stats.pointee.received_bytes)))
            }
            return 0
        }
    }
}
