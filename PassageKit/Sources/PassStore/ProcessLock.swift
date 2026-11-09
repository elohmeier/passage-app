import Foundation

/// An exclusive advisory lock (`flock`) on a file, shared by the app and its extensions so
/// only one of them writes to the git clone at a time. Each `withLock` opens its own file
/// description, so holders in the same process exclude each other too.
public struct ProcessLock: Sendable {
    public let path: String

    public init(path: String) {
        self.path = path
    }

    nonisolated(nonsending) public func withLock<T>(timeout: Duration = .seconds(30), _ body: () async throws -> T) async throws -> T {
        let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        // Poll rather than block, so no cooperative-pool thread waits on another process.
        let deadline = ContinuousClock.now + timeout
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK, ContinuousClock.now < deadline else { throw LockTimeout() }
            try await Task.sleep(for: .milliseconds(50))
        }
        defer { flock(fd, LOCK_UN) }
        return try await body()
    }

    public struct LockTimeout: Error, LocalizedError {
        public var errorDescription: String? { "Another part of Passage is still syncing. Try again in a moment." }
    }
}
