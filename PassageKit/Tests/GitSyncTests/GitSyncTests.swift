import CryptoKit
import Foundation
import NIOSSH
import Synchronization
import Testing

@testable import GitSync

/// Builds fixture repositories with the git CLI.
struct Fixture {
    let dir: URL
    var origin: URL { dir.appending(path: "origin.git") }
    var work: URL { dir.appending(path: "work") }

    init() throws {
        dir = FileManager.default.temporaryDirectory.appending(path: "gitsync-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try git(["init", "--bare", "-b", "main", origin.path])
        try git(["clone", origin.path, work.path])
        try commit("bank.age", "first")
        try git(["push", "origin", "main"], in: work)
    }

    /// Commits a file in the CLI working copy (playing "the desktop").
    func commit(_ path: String, _ content: String) throws {
        let url = work.appending(path: path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(content.utf8).write(to: url)
        try git(["add", path], in: work)
        try git(["-c", "user.name=Desktop", "-c", "user.email=d@example.com", "commit", "-q", "-m", "Edit \(path)"], in: work)
    }

    func push() throws { try git(["push", "-q", "origin", "main"], in: work) }

    @discardableResult
    func git(_ args: [String], in cwd: URL? = nil) throws -> String {
        let p = Process()
        p.executableURL = URL(filePath: "/usr/bin/git")
        p.arguments = (cwd.map { ["-C", $0.path] } ?? []) + args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = Pipe()
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw GitError(kind: .other, message: "git \(args) failed") }
        return String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }
}

@Suite struct GitRepoTests {
    let fx: Fixture
    let clone: URL

    init() throws {
        fx = try Fixture()
        clone = fx.dir.appending(path: "clone")
    }

    @Test func version() {
        #expect(GitSync.libgit2Version == "1.9.2")
    }

    @Test func cloneHead() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        #expect(FileManager.default.fileExists(atPath: clone.appending(path: "bank.age").path))
        #expect(await repo.branch == "main")
        let head = try await repo.headCommit()
        #expect(head.summary == "Edit bank.age")
        #expect(head.author == "Desktop")
        #expect(head.id.count == 40)
    }

    @Test func pullFastForwards() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        #expect(try await repo.pull(credentials: .none) == .upToDate)

        try fx.commit("email/alice.age", "new")
        try fx.push()
        let before = try await repo.headCommit().id
        guard case .fastForwarded(let from, let to) = try await repo.pull(credentials: .none) else {
            Issue.record("expected fast-forward")
            return
        }
        #expect(from == before)
        #expect(to == (try await repo.headCommit().id))
        #expect(FileManager.default.fileExists(atPath: clone.appending(path: "email/alice.age").path))
    }

    @Test func divergedHistoryIsReported() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        // A local commit on the phone…
        try fx.git(["-c", "user.name=Phone", "-c", "user.email=p@example.com", "commit", "-q", "--allow-empty", "-m", "local"], in: clone)
        // …and a different one on the desktop.
        try fx.commit("bank.age", "changed on desktop")
        try fx.push()
        await #expect(throws: GitError.self) { try await repo.pull(credentials: .none) }
        do {
            _ = try await repo.pull(credentials: .none)
        } catch {
            #expect(error.kind == .diverged)
        }
    }

    @Test func localModificationsAreNotOverwritten() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        try Data("edited on phone, uncommitted".utf8).write(to: clone.appending(path: "bank.age"))
        try fx.commit("bank.age", "changed on desktop")
        try fx.push()
        await #expect(throws: GitError.self) { try await repo.pull(credentials: .none) }
        #expect(try String(contentsOf: clone.appending(path: "bank.age"), encoding: .utf8) == "edited on phone, uncommitted")
    }

    @Test func failedCloneCleansUp() async throws {
        await #expect(throws: GitError.self) {
            try await GitRepo.clone(remote: fx.dir.appending(path: "missing.git").path, into: clone)
        }
        #expect(!FileManager.default.fileExists(atPath: clone.path))
    }

    /// Real HTTPS through Secure Transport. Needs network; opt in with GITSYNC_NETWORK_TESTS=1.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["GITSYNC_NETWORK_TESTS"] == "1"))
    func httpsClone() async throws {
        // The local transport doesn't report progress; HTTPS does.
        let progress = Mutex<[GitProgress]>([])
        let repo = try await GitRepo.clone(remote: "https://github.com/FiloSottile/passage.git", into: clone) { p in
            progress.withLock { $0.append(p) }
        }
        #expect(try await repo.headCommit().id.count == 40)
        #expect(progress.withLock { $0.last?.fraction } == 1)
        #expect(try await repo.pull(credentials: .none) == .upToDate)
    }
}

@Suite struct SSHURLTests {
    @Test func parses() {
        #expect(SSHURL("git@github.com:alice/pass.git") == SSHURL(user: "git", host: "github.com", port: 22, path: "alice/pass.git"))
        #expect(SSHURL("ssh://git@example.com:2222/srv/pass.git") == SSHURL(user: "git", host: "example.com", port: 2222, path: "/srv/pass.git"))
        #expect(SSHURL("ssh://example.com/~/pass.git")?.path == "~/pass.git")
        #expect(SSHURL("example.com:pass")?.user == nil)
        #expect(SSHURL("nohost") == nil)
    }
}

@Suite struct KnownHostsTests {
    /// Must match https://api.github.com/meta `ssh_key_fingerprints`.
    @Test func pinnedGitHubFingerprints() {
        let fingerprints = Set(KnownHosts.pinned.map(\.fingerprint))
        #expect(fingerprints == ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"])
    }

    @Test func status() {
        var hosts = KnownHosts()
        let key = HostKey(host: "example.com", key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")
        #expect(hosts.status(of: key) == .unknown)
        hosts.trust(key)
        #expect(hosts.status(of: key) == .trusted)
        #expect(hosts.status(of: HostKey(host: "example.com", key: "ssh-ed25519 AAAAother")) == .mismatch)
        #expect(hosts.status(of: HostKey(host: "github.com", key: "ssh-ed25519 AAAAevil")) == .mismatch, "pinned host")
    }
}

/// Clones and pulls over SSH through our transport, against an in-process swift-nio-ssh server.
@Suite(.serialized) struct SSHTransportTests {
    let fx: Fixture
    let clone: URL
    let key = SSHKey.generateEd25519()
    let server: SSHTestServer

    init() throws {
        fx = try Fixture()
        clone = fx.dir.appending(path: "clone")
        server = try SSHTestServer(authorizedKey: try key.privateKey().publicKey)
    }

    var url: String { "ssh://git@127.0.0.1:\(server.port)\(fx.origin.path)" }
    var serverKey: HostKey { HostKey(host: "[127.0.0.1]:\(server.port)", key: server.hostKey.publicKey) }

    @Test func unknownHostKeyIsReportedWithFingerprint() async throws {
        defer { server.stop() }
        do {
            _ = try await GitRepo.clone(remote: url, into: clone, credentials: .ssh(username: nil, key: key))
            Issue.record("expected an unknown host key error")
        } catch {
            #expect(error.kind == .unknownHostKey(serverKey))
            #expect(error.localizedDescription.contains(serverKey.fingerprint))
        }
        #expect(!FileManager.default.fileExists(atPath: clone.path))
    }

    @Test func cloneAndPullWithTrustedHost() async throws {
        defer { server.stop() }
        let hosts = KnownHosts([serverKey])
        let repo = try await GitRepo.clone(remote: url, into: clone, credentials: .ssh(username: nil, key: key), knownHosts: hosts)
        #expect(try await repo.headCommit().summary == "Edit bank.age")

        try fx.commit("email/alice.age", "new")
        try fx.push()
        guard case .fastForwarded = try await repo.pull(credentials: .ssh(username: nil, key: key), knownHosts: hosts) else {
            Issue.record("expected fast-forward")
            return
        }
        #expect(FileManager.default.fileExists(atPath: clone.appending(path: "email/alice.age").path))
    }

    @Test func wrongKeyIsAnAuthenticationError() async throws {
        defer { server.stop() }
        await #expect(throws: GitError(kind: .authentication, message: "the server rejected the SSH key")) {
            try await GitRepo.clone(
                remote: url, into: clone, credentials: .ssh(username: nil, key: .generateEd25519()), knownHosts: KnownHosts([serverKey]))
        }
    }

    @Test func secureEnclaveKey() async throws {
        defer { server.stop() }
        guard SecureEnclave.isAvailable else { return }
        let seKey = try SSHKey.generateSecureEnclave()
        let seServer = try SSHTestServer(authorizedKey: try seKey.privateKey().publicKey)
        defer { seServer.stop() }
        let hostKey = HostKey(host: "[127.0.0.1]:\(seServer.port)", key: seServer.hostKey.publicKey)
        let repo = try await GitRepo.clone(
            remote: "ssh://git@127.0.0.1:\(seServer.port)\(fx.origin.path)", into: clone,
            credentials: .ssh(username: nil, key: seKey), knownHosts: KnownHosts([hostKey]))
        #expect(try await repo.headCommit().id.count == 40)
        #expect(try seKey.publicKeyLine(comment: "iPhone").hasPrefix("ecdsa-sha2-nistp256 AAAA"))
    }
}

/// Against github.com: the pinned host key must verify, and an unregistered key must be
/// rejected as an authentication failure. Opt in with GITSYNC_NETWORK_TESTS=1.
@Test(.enabled(if: ProcessInfo.processInfo.environment["GITSYNC_NETWORK_TESTS"] == "1"))
func gitHubSSHHostKeyIsPinned() async throws {
    let dir = FileManager.default.temporaryDirectory.appending(path: "gh-\(UUID().uuidString)")
    await #expect(throws: GitError(kind: .authentication, message: "the server rejected the SSH key")) {
        try await GitRepo.clone(remote: "git@github.com:FiloSottile/passage.git", into: dir, credentials: .ssh(username: nil, key: .generateEd25519()))
    }
}

@Suite struct GitWriteTests {
    let fx: Fixture
    let clone: URL
    let phone = GitRepo.Signature(name: "Passage on iPhone", email: "passage@iphone.invalid")
    let date = Date(timeIntervalSince1970: 1_800_000_000)

    init() throws {
        fx = try Fixture()
        clone = fx.dir.appending(path: "clone")
    }

    func write(_ path: String, _ content: String) throws {
        let url = clone.appending(path: path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(content.utf8).write(to: url)
    }

    func desktopFile(_ path: String) throws -> String? {
        try fx.git(["pull", "-q", "origin", "main"], in: fx.work)
        let url = fx.work.appending(path: path)
        return FileManager.default.fileExists(atPath: url.path) ? try String(contentsOf: url, encoding: .utf8) : nil
    }

    @Test func commitAllStagesAddsAndDeletes() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        #expect(try await repo.commitAll(message: "nothing", author: phone) == nil)

        try write("email/alice.age", "new")
        try FileManager.default.removeItem(at: clone.appending(path: "bank.age"))
        let id = try await repo.commitAll(message: "Add given password for email/alice to store.", author: phone, date: date)
        #expect(id?.count == 40)
        let head = try await repo.headCommit()
        #expect(head.author == "Passage on iPhone")
        #expect(head.summary == "Add given password for email/alice to store.")
        #expect(try fx.git(["status", "--porcelain"], in: clone).isEmpty)

        let result = try await repo.sync(credentials: .none, author: phone)
        #expect(result == GitRepo.SyncResult(pulled: false, pushed: true))
        #expect(try desktopFile("email/alice.age") == "new")
        #expect(try desktopFile("bank.age") == nil)
    }

    @Test func divergedWithoutConflictMerges() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        try write("phone.age", "from phone")
        try await repo.commitAll(message: "phone", author: phone)
        try fx.commit("desktop.age", "from desktop")
        try fx.push()

        let result = try await repo.sync(credentials: .none, author: phone, date: date)
        #expect(result.pulled && result.pushed && result.conflictCopies.isEmpty)
        #expect(FileManager.default.fileExists(atPath: clone.appending(path: "desktop.age").path))
        #expect(try desktopFile("phone.age") == "from phone")
        #expect(try await repo.headCommit().summary == "Merge remote changes")
    }

    @Test func conflictingEditsKeepBothVersions() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        try write("bank.age", "phone version")
        try await repo.commitAll(message: "phone edit", author: phone)
        try fx.commit("bank.age", "desktop version")
        try fx.push()

        let result = try await repo.sync(credentials: .none, author: phone, date: date)
        let copy = "bank (\(GitRepo.conflictSuffix(date))).age"
        #expect(result.conflictCopies == [copy])
        #expect(try String(contentsOf: clone.appending(path: "bank.age"), encoding: .utf8) == "desktop version")
        #expect(try String(contentsOf: clone.appending(path: copy), encoding: .utf8) == "phone version")
        #expect(try desktopFile(copy) == "phone version", "the conflict copy is pushed too")
        #expect(try fx.git(["status", "--porcelain"], in: clone).isEmpty, "no leftover merge state")
        #expect(!FileManager.default.fileExists(atPath: clone.appending(path: ".git/MERGE_HEAD").path))
    }

    @Test func deleteVersusEditKeepsTheEdit() async throws {
        let repo = try await GitRepo.clone(remote: fx.origin.path, into: clone)
        try write("bank.age", "edited on phone")
        try await repo.commitAll(message: "phone edit", author: phone)
        try fx.git(["rm", "-q", "bank.age"], in: fx.work)
        try fx.git(["-c", "user.name=Desktop", "-c", "user.email=d@example.com", "commit", "-q", "-m", "remove bank"], in: fx.work)
        try fx.push()

        let result = try await repo.sync(credentials: .none, author: phone, date: date)
        #expect(result.conflictCopies.isEmpty)
        #expect(try desktopFile("bank.age") == "edited on phone")
    }

    @Test func conflictCopyNames() {
        #expect(GitRepo.conflictCopyPath("a/b/work.age", suffix: "conflict X") == "a/b/work (conflict X).age")
        #expect(GitRepo.conflictCopyPath(".age-recipients", suffix: "conflict X") == ".age-recipients (conflict X)")
        #expect(GitRepo.conflictCopyPath("README.md", suffix: "conflict X") == "README.md (conflict X)")
    }
}

extension SSHTransportTests {
    @Test func pushOverSSH() async throws {
        defer { server.stop() }
        let hosts = KnownHosts([serverKey])
        let credentials = GitCredentials.ssh(username: nil, key: key)
        let repo = try await GitRepo.clone(remote: url, into: clone, credentials: credentials, knownHosts: hosts)
        try Data("over ssh".utf8).write(to: clone.appending(path: "ssh.age"))
        try await repo.commitAll(message: "ssh push", author: .init(name: "Phone", email: "p@example.com"))
        let result = try await repo.sync(credentials: credentials, knownHosts: hosts, author: .init(name: "Phone", email: "p@example.com"))
        #expect(result.pushed)
        try fx.git(["pull", "-q", "origin", "main"], in: fx.work)
        #expect(FileManager.default.fileExists(atPath: fx.work.appending(path: "ssh.age").path))
    }
}
