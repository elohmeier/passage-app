import CGit2
import Foundation

/// How to authenticate to a remote.
public enum GitCredentials: Sendable, Equatable {
    case none
    /// HTTPS basic auth. For GitHub/GitLab/Gitea, the password is a personal access token.
    case userPassword(username: String, password: String)
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
    let progress: (@Sendable (GitProgress) -> Void)?
    var credentialAttempts = 0
    var cancelled: () -> Bool

    init(credentials: GitCredentials, progress: (@Sendable (GitProgress) -> Void)?, cancelled: @escaping () -> Bool = { Task.isCancelled }) {
        self.credentials = credentials
        self.progress = progress
        self.cancelled = cancelled
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
