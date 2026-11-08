import CGit2
import Foundation

/// A local clone of a password store.
///
/// libgit2 objects aren't thread-safe, so all access goes through this actor. Blocking libgit2
/// calls run on the actor's executor, off the main thread.
public actor GitRepo {
    public let url: URL
    private let handle: RepoHandle
    private var repo: OpaquePointer { handle.pointer }

    public struct Commit: Sendable, Equatable {
        public let id: String
        public let summary: String
        public let author: String
        public let date: Date
    }

    public enum PullResult: Sendable, Equatable {
        case upToDate
        case fastForwarded(from: String, to: String)
    }

    /// Opens an existing clone.
    public init(opening url: URL) throws(GitError) {
        _ = GitSync.initialized
        var repo: OpaquePointer?
        try check(git_repository_open(&repo, url.path))
        self.url = url
        handle = RepoHandle(repo!)
    }

    /// Clones `remote` into `directory`, which must not exist or be empty.
    public static func clone(
        remote: String, into directory: URL, branch: String? = nil, credentials: GitCredentials = .none,
        progress: (@Sendable (GitProgress) -> Void)? = nil
    ) async throws(GitError) -> GitRepo {
        _ = GitSync.initialized
        let ctx = CallbackContext(credentials: credentials, progress: progress)
        var options = git_clone_options()
        try check(git_clone_options_init(&options, UInt32(GIT_CLONE_OPTIONS_VERSION)))
        ctx.install(into: &options.fetch_opts.callbacks)
        options.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE.rawValue

        var repo: OpaquePointer?
        let code: Int32 = withExtendedLifetime(ctx) {
            if let branch {
                return branch.withCString { b in
                    options.checkout_branch = b
                    return git_clone(&repo, remote, directory.path, &options)
                }
            }
            return git_clone(&repo, remote, directory.path, &options)
        }
        if code < 0 {
            let error = GitError.last(code)
            // Don't leave a half-cloned directory behind.
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
        git_repository_free(repo)
        return try GitRepo(opening: directory)
    }

    // MARK: Reading

    /// The current branch name, or nil if HEAD is detached.
    public var branch: String? {
        var head: OpaquePointer?
        guard git_repository_head(&head, repo) == 0 else { return nil }
        defer { git_reference_free(head) }
        guard git_reference_is_branch(head) == 1 else { return nil }
        return git_reference_shorthand(head).map { String(cString: $0) }
    }

    public func headCommit() throws(GitError) -> Commit {
        var oid = git_oid()
        try check(git_reference_name_to_id(&oid, repo, "HEAD"))
        return try commit(oid)
    }

    public var remoteURL: String? {
        var remote: OpaquePointer?
        guard git_remote_lookup(&remote, repo, "origin") == 0 else { return nil }
        defer { git_remote_free(remote) }
        return git_remote_url(remote).map { String(cString: $0) }
    }

    // MARK: Syncing

    /// Fetches `origin`.
    public func fetch(credentials: GitCredentials, progress: (@Sendable (GitProgress) -> Void)? = nil) throws(GitError) {
        var remote: OpaquePointer?
        try check(git_remote_lookup(&remote, repo, "origin"))
        defer { git_remote_free(remote) }

        let ctx = CallbackContext(credentials: credentials, progress: progress)
        var options = git_fetch_options()
        try check(git_fetch_options_init(&options, UInt32(GIT_FETCH_OPTIONS_VERSION)))
        ctx.install(into: &options.callbacks)
        options.prune = GIT_FETCH_PRUNE
        let code = withExtendedLifetime(ctx) { git_remote_fetch(remote, nil, &options, nil) }
        try check(code)
    }

    /// Fetches and fast-forwards the current branch to its upstream. Throws `.diverged` if
    /// both sides have new commits (merging is a later milestone).
    public func pull(credentials: GitCredentials, progress: (@Sendable (GitProgress) -> Void)? = nil) throws(GitError) -> PullResult {
        try fetch(credentials: credentials, progress: progress)

        var head: OpaquePointer?
        try check(git_repository_head(&head, repo))
        defer { git_reference_free(head) }
        var upstream: OpaquePointer?
        try check(git_branch_upstream(&upstream, head))
        defer { git_reference_free(upstream) }

        var annotated: OpaquePointer?
        try check(git_annotated_commit_from_ref(&annotated, repo, upstream))
        defer { git_annotated_commit_free(annotated) }

        var analysis = git_merge_analysis_t(0)
        var preference = git_merge_preference_t(0)
        var heads: [OpaquePointer?] = [annotated]
        try check(git_merge_analysis(&analysis, &preference, repo, &heads, 1))

        if analysis.rawValue & GIT_MERGE_ANALYSIS_UP_TO_DATE.rawValue != 0 { return .upToDate }
        guard analysis.rawValue & GIT_MERGE_ANALYSIS_FASTFORWARD.rawValue != 0 else {
            throw GitError(kind: .diverged, message: "local and remote branches have diverged")
        }

        let target = git_annotated_commit_id(annotated)!.pointee
        let from = Self.hex(git_reference_target(head)!.pointee)

        // Check out the new tree first; SAFE refuses to overwrite local modifications.
        var commit: OpaquePointer?
        var targetOID = target
        try check(git_commit_lookup(&commit, repo, &targetOID))
        defer { git_commit_free(commit) }
        var checkout = git_checkout_options()
        try check(git_checkout_options_init(&checkout, UInt32(GIT_CHECKOUT_OPTIONS_VERSION)))
        checkout.checkout_strategy = GIT_CHECKOUT_SAFE.rawValue
        try check(git_checkout_tree(repo, commit, &checkout))

        var updated: OpaquePointer?
        try check(git_reference_set_target(&updated, head, &targetOID, "pull: fast-forward"))
        git_reference_free(updated)
        return .fastForwarded(from: from, to: Self.hex(target))
    }

    // MARK: Helpers

    private func commit(_ oid: git_oid) throws(GitError) -> Commit {
        var oid = oid
        var commit: OpaquePointer?
        try check(git_commit_lookup(&commit, repo, &oid))
        defer { git_commit_free(commit) }
        let author = git_commit_author(commit)!.pointee
        return Commit(
            id: Self.hex(oid), summary: git_commit_summary(commit).map { String(cString: $0) } ?? "",
            author: author.name.map { String(cString: $0) } ?? "",
            date: Date(timeIntervalSince1970: TimeInterval(git_commit_time(commit))))
    }

    static func hex(_ oid: git_oid) -> String {
        var oid = oid
        var buffer = [CChar](repeating: 0, count: Int(GIT_OID_MAX_HEXSIZE) + 1)
        git_oid_tostr(&buffer, buffer.count, &oid)
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

/// Owns a `git_repository *`. Only used from `GitRepo`'s isolation.
private final class RepoHandle: @unchecked Sendable {
    let pointer: OpaquePointer
    init(_ pointer: OpaquePointer) { self.pointer = pointer }
    deinit { git_repository_free(pointer) }
}
