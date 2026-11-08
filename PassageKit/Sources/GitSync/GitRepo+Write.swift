import CGit2
import Foundation

extension GitRepo {
    public struct Signature: Sendable, Equatable {
        public var name: String
        public var email: String

        public init(name: String, email: String) {
            self.name = name
            self.email = email
        }
    }

    public struct SyncResult: Sendable, Equatable {
        public var pulled = false
        public var pushed = false
        /// Conflict copies created while merging, relative paths.
        public var conflictCopies: [String] = []
    }

    // MARK: Committing

    /// Stages every change in the working tree (new, modified, deleted) and commits it.
    /// Returns the new commit's id, or nil if there was nothing to commit.
    @discardableResult
    public func commitAll(message: String, author: Signature, date: Date = .now) throws(GitError) -> String? {
        let index = try openIndex()
        defer { git_index_free(index) }
        try check(git_index_add_all(index, nil, GIT_INDEX_ADD_DEFAULT.rawValue, nil, nil))
        try check(git_index_update_all(index, nil, nil, nil))
        try check(git_index_write(index))

        var tree = git_oid()
        try check(git_index_write_tree(&tree, index))
        let head = try oid("HEAD")
        var headTree = try treeID(of: head)
        if git_oid_equal(&headTree, &tree) == 1 { return nil }
        return try commit(tree: tree, parents: [head], message: message, author: author, date: date)
    }

    // MARK: Pushing

    /// Pushes the current branch to `origin`.
    public func push(credentials: GitCredentials, knownHosts: KnownHosts = KnownHosts()) throws(GitError) {
        guard let branch else { throw GitError(kind: .other, message: "HEAD is detached") }
        var remote: OpaquePointer?
        try check(git_remote_lookup(&remote, repo, "origin"))
        defer { git_remote_free(remote) }

        let ctx = CallbackContext(credentials: credentials, knownHosts: knownHosts, progress: nil)
        var options = git_push_options()
        try check(git_push_options_init(&options, UInt32(GIT_PUSH_OPTIONS_VERSION)))
        ctx.install(into: &options.callbacks)

        let refspec = "refs/heads/\(branch):refs/heads/\(branch)"
        let code: Int32 = withExtendedLifetime(ctx) {
            refspec.withCString { spec in
                var strings: [UnsafeMutablePointer<CChar>?] = [UnsafeMutablePointer(mutating: spec)]
                return strings.withUnsafeMutableBufferPointer { buffer in
                    var array = git_strarray(strings: buffer.baseAddress, count: 1)
                    return git_remote_push(remote, &array, &options)
                }
            }
        }
        if code < 0 {
            let error = ctx.error(code)
            throw code == GIT_ENONFASTFORWARD.rawValue ? GitError(kind: .pushRejected, message: error.message) : error
        }
        if let rejection = ctx.pushRejection {
            throw GitError(kind: .pushRejected, message: rejection)
        }
    }

    // MARK: Syncing

    /// Fetches, integrates remote changes (fast-forward, or a merge that keeps both sides of
    /// conflicting files), and pushes local commits. Retries once if the push races another
    /// device.
    public func sync(
        credentials: GitCredentials, knownHosts: KnownHosts = KnownHosts(), author: Signature, date: Date = .now
    ) throws(GitError) -> SyncResult {
        var result = SyncResult()
        for attempt in 0..<2 {
            try fetch(credentials: credentials, knownHosts: knownHosts)
            let local = try oid("HEAD")
            guard let upstream = try upstreamID() else {
                // A brand-new branch: nothing to pull, just publish it.
                try push(credentials: credentials, knownHosts: knownHosts)
                result.pushed = true
                return result
            }
            var ahead = 0, behind = 0
            var l = local, u = upstream
            try check(git_graph_ahead_behind(&ahead, &behind, repo, &l, &u))

            if behind > 0 {
                if ahead == 0 {
                    try fastForward(to: upstream)
                } else {
                    result.conflictCopies += try merge(upstream, author: author, date: date)
                }
                result.pulled = true
            }
            guard ahead > 0 else { return result }
            do {
                try push(credentials: credentials, knownHosts: knownHosts)
                result.pushed = true
                return result
            } catch where error.kind == .pushRejected && attempt == 0 {
                continue
            }
        }
        return result
    }

    /// Commits ahead of / behind the upstream branch, from the last fetch.
    public func aheadBehind() throws(GitError) -> (ahead: Int, behind: Int) {
        guard let upstream = try upstreamID() else { return (0, 0) }
        var ahead = 0, behind = 0
        var l = try oid("HEAD"), u = upstream
        try check(git_graph_ahead_behind(&ahead, &behind, repo, &l, &u))
        return (ahead, behind)
    }

    // MARK: Merging

    /// Merges `upstream` into HEAD. Conflicting files keep the upstream version at their path
    /// and our version as a sibling "conflict" copy; a file deleted on one side and changed on
    /// the other keeps the changed version. Returns the conflict copies' paths.
    func merge(_ upstream: git_oid, author: Signature, date: Date) throws(GitError) -> [String] {
        var annotated: OpaquePointer?
        var target = upstream
        try check(git_annotated_commit_lookup(&annotated, repo, &target))
        defer { git_annotated_commit_free(annotated) }

        var mergeOptions = git_merge_options()
        try check(git_merge_options_init(&mergeOptions, UInt32(GIT_MERGE_OPTIONS_VERSION)))
        var checkout = git_checkout_options()
        try check(git_checkout_options_init(&checkout, UInt32(GIT_CHECKOUT_OPTIONS_VERSION)))
        checkout.checkout_strategy = GIT_CHECKOUT_SAFE.rawValue | GIT_CHECKOUT_ALLOW_CONFLICTS.rawValue
        var heads: [OpaquePointer?] = [annotated]
        try check(git_merge(repo, &heads, 1, &mergeOptions, &checkout))
        defer { git_repository_state_cleanup(repo) }

        let index = try openIndex()
        defer { git_index_free(index) }
        var copies: [String] = []
        if git_index_has_conflicts(index) == 1 {
            let suffix = Self.conflictSuffix(date)
            for conflict in try conflicts(in: index) {
                switch (conflict.ours, conflict.theirs) {
                case (let ours?, let theirs?):
                    try writeBlob(theirs, to: conflict.path)
                    let copy = Self.conflictCopyPath(conflict.path, suffix: suffix)
                    try writeBlob(ours, to: copy)
                    copies.append(copy)
                case (let ours?, nil):
                    try writeBlob(ours, to: conflict.path)
                case (nil, let theirs?):
                    try writeBlob(theirs, to: conflict.path)
                case (nil, nil):
                    break
                }
                try check(git_index_conflict_remove(index, conflict.path))
            }
            try check(git_index_add_all(index, nil, GIT_INDEX_ADD_DEFAULT.rawValue, nil, nil))
            try check(git_index_write(index))
        }

        var tree = git_oid()
        try check(git_index_write_tree(&tree, index))
        let message = copies.isEmpty
            ? "Merge remote changes"
            : "Merge remote changes\n\nConflicting edits kept as:\n" + copies.map { "- \($0)" }.joined(separator: "\n")
        _ = try commit(tree: tree, parents: [try oid("HEAD"), upstream], message: message, author: author, date: date)
        return copies
    }

    struct Conflict {
        let path: String
        let ours: git_oid?
        let theirs: git_oid?
    }

    private func conflicts(in index: OpaquePointer?) throws(GitError) -> [Conflict] {
        var iterator: OpaquePointer?
        try check(git_index_conflict_iterator_new(&iterator, index))
        defer { git_index_conflict_iterator_free(iterator) }
        var result: [Conflict] = []
        var ancestor: UnsafePointer<git_index_entry>?, ours: UnsafePointer<git_index_entry>?, theirs: UnsafePointer<git_index_entry>?
        while git_index_conflict_next(&ancestor, &ours, &theirs, iterator) == 0 {
            guard let path = (ours ?? theirs ?? ancestor)?.pointee.path.map({ String(cString: $0) }) else { continue }
            result.append(Conflict(path: path, ours: ours?.pointee.id, theirs: theirs?.pointee.id))
        }
        return result
    }

    /// `email/work.age` → `email/work (conflict 2026-11-08 1612).age`; other files get the
    /// suffix appended (`.age-recipients (conflict …)`).
    static func conflictCopyPath(_ path: String, suffix: String) -> String {
        if path.hasSuffix(".age"), !(path as NSString).lastPathComponent.hasPrefix(".") {
            return String(path.dropLast(4)) + " (\(suffix)).age"
        }
        return path + " (\(suffix))"
    }

    static func conflictSuffix(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HHmm"
        return "conflict " + f.string(from: date)
    }

    // MARK: Helpers

    func fastForward(to target: git_oid) throws(GitError) {
        var head: OpaquePointer?
        try check(git_repository_head(&head, repo))
        defer { git_reference_free(head) }
        var targetOID = target
        var commit: OpaquePointer?
        try check(git_commit_lookup(&commit, repo, &targetOID))
        defer { git_commit_free(commit) }
        var checkout = git_checkout_options()
        try check(git_checkout_options_init(&checkout, UInt32(GIT_CHECKOUT_OPTIONS_VERSION)))
        checkout.checkout_strategy = GIT_CHECKOUT_SAFE.rawValue
        try check(git_checkout_tree(repo, commit, &checkout))
        var updated: OpaquePointer?
        try check(git_reference_set_target(&updated, head, &targetOID, "sync: fast-forward"))
        git_reference_free(updated)
    }

    func upstreamID() throws(GitError) -> git_oid? {
        var head: OpaquePointer?
        try check(git_repository_head(&head, repo))
        defer { git_reference_free(head) }
        var upstream: OpaquePointer?
        guard git_branch_upstream(&upstream, head) == 0 else { return nil }
        defer { git_reference_free(upstream) }
        return git_reference_target(upstream)?.pointee
    }

    func oid(_ ref: String) throws(GitError) -> git_oid {
        var oid = git_oid()
        try check(git_reference_name_to_id(&oid, repo, ref))
        return oid
    }

    private func openIndex() throws(GitError) -> OpaquePointer? {
        var index: OpaquePointer?
        try check(git_repository_index(&index, repo))
        return index
    }

    private func treeID(of commitID: git_oid) throws(GitError) -> git_oid {
        var id = commitID
        var commit: OpaquePointer?
        try check(git_commit_lookup(&commit, repo, &id))
        defer { git_commit_free(commit) }
        return git_commit_tree_id(commit)!.pointee
    }

    private func commit(tree: git_oid, parents: [git_oid], message: String, author: Signature, date: Date) throws(GitError) -> String {
        var treeID = tree
        var treeObject: OpaquePointer?
        try check(git_tree_lookup(&treeObject, repo, &treeID))
        defer { git_tree_free(treeObject) }

        var parentCommits: [OpaquePointer?] = []
        defer { parentCommits.forEach { git_commit_free($0) } }
        for parent in parents {
            var p = parent
            var commit: OpaquePointer?
            try check(git_commit_lookup(&commit, repo, &p))
            parentCommits.append(commit)
        }

        var signature: UnsafeMutablePointer<git_signature>?
        let offset = Int32(TimeZone.current.secondsFromGMT(for: date) / 60)
        try check(git_signature_new(&signature, author.name, author.email, git_time_t(date.timeIntervalSince1970), offset))
        defer { git_signature_free(signature) }

        var id = git_oid()
        let parentArray = UnsafeMutablePointer<OpaquePointer?>.allocate(capacity: parentCommits.count)
        defer { parentArray.deallocate() }
        parentArray.initialize(from: parentCommits, count: parentCommits.count)
        try check(git_commit_create(&id, repo, "HEAD", signature, signature, nil, message, treeObject, parentCommits.count, parentArray))
        return Self.hex(id)
    }

    private func writeBlob(_ id: git_oid, to path: String) throws(GitError) {
        var oid = id
        var blob: OpaquePointer?
        try check(git_blob_lookup(&blob, repo, &oid))
        defer { git_blob_free(blob) }
        let data = Data(bytes: git_blob_rawcontent(blob), count: Int(git_blob_rawsize(blob)))
        let url = self.url.appending(path: path)
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: url, options: .atomic)
        } catch {
            throw GitError(kind: .other, message: "couldn't write \(path): \(error.localizedDescription)")
        }
    }
}
