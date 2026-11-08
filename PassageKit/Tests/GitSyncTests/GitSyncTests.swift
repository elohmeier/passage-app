import Foundation
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
