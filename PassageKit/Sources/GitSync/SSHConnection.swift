import Foundation
import NIOCore
import NIOSSH
import NIOTransportServices

enum SSHFailure: Error, Equatable {
    case hostKey(HostKey, KnownHosts.Status)
    case authentication
    case timeout
    case connection(String)
    /// The remote command failed, with its stderr (e.g. "ERROR: Repository not found.").
    case remote(String)
}

/// A blocking SSH client for libgit2's transport callbacks, which run on libgit2's thread.
/// The NIO event loop does the I/O; this class hands bytes across with a condition variable.
final class SSHConnection: @unchecked Sendable {
    private let channel: Channel

    /// Connects and authenticates. `validateHostKey` runs on the event loop before any
    /// authentication data is sent; returning a failure aborts the connection. Returns once
    /// user authentication has succeeded.
    static func connect(
        host: String, port: Int, username: String, key: NIOSSHPrivateKey, timeout: TimeAmount = .seconds(20),
        validateHostKey: @escaping @Sendable (NIOSSHPublicKey) -> SSHFailure?
    ) throws(SSHFailure) -> SSHConnection {
        let failure = FailureBox()
        let group = NIOTSEventLoopGroup.singleton
        let authenticated = OutcomeBox<Void>()
        let bootstrap = NIOTSConnectionBootstrap(group: group)
            .connectTimeout(timeout)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let handler = NIOSSHHandler(
                        role: .client(.init(
                            userAuthDelegate: OneKeyAuthDelegate(username: username, key: key, failure: failure),
                            serverAuthDelegate: HostKeyDelegate(validate: validateHostKey, failure: failure))),
                        allocator: channel.allocator, inboundChildChannelInitializer: nil)
                    try channel.pipeline.syncOperations.addHandlers(handler, AuthWatcher(promise: authenticated, failure: failure))
                }
            }
        // Fail fast instead of letting Network.framework wait for connectivity (it would keep a
        // dropped connection "waiting" forever, e.g. right after the device wakes up), and
        // enforce our own deadline on top of NIO's connect timeout.
        let connecting = bootstrap.channelOption(NIOTSChannelOptions.waitForActivity, value: false)
            .connect(host: host, port: port)
        let outcome = OutcomeBox<Channel>()
        connecting.whenComplete { outcome.set($0) }
        guard let result = outcome.wait(timeout: timeout) else {
            connecting.whenSuccess { $0.close(promise: nil) }
            throw .timeout
        }
        let channel: Channel
        do {
            channel = try result.get()
        } catch {
            throw failure.value ?? .connection("\(host):\(port): \(error)")
        }
        // Done when authentication succeeds, the connection closes, or the deadline passes,
        // whichever comes first. (A close before the SSH handshake isn't forwarded past
        // NIOSSHHandler, so the close future is watched directly.)
        channel.closeFuture.whenComplete { _ in authenticated.set(.failure(failure.value ?? .connection("connection closed"))) }
        guard let auth = authenticated.wait(timeout: timeout) else {
            channel.close(promise: nil)
            throw failure.value ?? .timeout
        }
        if case .failure(let error) = auth {
            channel.close(promise: nil)
            throw failure.value ?? (error as? SSHFailure) ?? .connection("\(error)")
        }
        return SSHConnection(channel: channel, failure: failure)
    }

    private let failure: FailureBox

    private init(channel: Channel, failure: FailureBox) {
        self.channel = channel
        self.failure = failure
    }

    /// Runs `command` and returns its stdin/stdout.
    func exec(_ command: String, timeout: TimeAmount = .seconds(20)) throws(SSHFailure) -> SSHExecStream {
        let stream = SSHExecStream()
        let loop = channel.eventLoop
        let opened = loop.makePromise(of: Channel.self)
        loop.execute {
            do {
                let handler = try self.channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
                handler.createChannel(opened, channelType: .session) { child, _ in
                    child.eventLoop.makeCompletedFuture {
                        try child.pipeline.syncOperations.addHandler(ExecHandler(stream: stream))
                    }
                }
            } catch {
                opened.fail(error)
            }
        }
        do {
            let child = try opened.futureResult.wait()
            stream.channel = child
            try child.triggerUserOutboundEvent(SSHChannelRequestEvent.ExecRequest(command: command, wantReply: false)).wait()
        } catch {
            throw failure.value ?? stream.failure ?? .connection("exec failed: \(error)")
        }
        return stream
    }

    func close() {
        channel.close(promise: nil)
    }

    /// Completes `promise` when user authentication succeeds, fails it if the connection
    /// errors or closes first.
    private final class AuthWatcher: ChannelInboundHandler {
        typealias InboundIn = Any
        let promise: OutcomeBox<Void>
        let failure: FailureBox

        init(promise: OutcomeBox<Void>, failure: FailureBox) {
            self.promise = promise
            self.failure = failure
        }

        func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
            if event is UserAuthSuccessEvent { promise.set(.success(())) }
            context.fireUserInboundEventTriggered(event)
        }

        func errorCaught(context: ChannelHandlerContext, error: Error) {
            finish(failure.value ?? .connection("\(error)"))
            context.close(promise: nil)
        }

        func channelInactive(context: ChannelHandlerContext) {
            finish(failure.value ?? .connection("connection closed"))
            context.fireChannelInactive()
        }

        private func finish(_ error: SSHFailure) {
            promise.set(.failure(error))
        }
    }

    /// The first result delivered, waited for with a deadline.
    private final class OutcomeBox<T>: @unchecked Sendable {
        private let condition = NSCondition()
        private var result: Result<T, any Error>?

        func set(_ r: Result<T, any Error>) {
            condition.withLock {
                if result == nil { result = r }
                condition.broadcast()
            }
        }

        func wait(timeout: TimeAmount) -> Result<T, any Error>? {
            let deadline = Date.now.addingTimeInterval(Double(timeout.nanoseconds) / 1e9)
            return condition.withLock {
                while result == nil, condition.wait(until: deadline) {}
                return result
            }
        }
    }

    private final class FailureBox: @unchecked Sendable {
        private let lock = NSLock()
        private var _value: SSHFailure?
        var value: SSHFailure? {
            get { lock.withLock { _value } }
            set { lock.withLock { _value = newValue } }
        }
    }

    private final class HostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
        let validate: @Sendable (NIOSSHPublicKey) -> SSHFailure?
        let failure: FailureBox

        init(validate: @escaping @Sendable (NIOSSHPublicKey) -> SSHFailure?, failure: FailureBox) {
            self.validate = validate
            self.failure = failure
        }

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            if let error = validate(hostKey) {
                failure.value = error
                validationCompletePromise.fail(error)
            } else {
                validationCompletePromise.succeed(())
            }
        }
    }

    /// Offers the one key once. If the server rejects it, authentication fails.
    private final class OneKeyAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
        let username: String
        let key: NIOSSHPrivateKey
        let failure: FailureBox
        var offered = false

        init(username: String, key: NIOSSHPrivateKey, failure: FailureBox) {
            self.username = username
            self.key = key
            self.failure = failure
        }

        func nextAuthenticationType(
            availableMethods: NIOSSHAvailableUserAuthenticationMethods,
            nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
        ) {
            guard !offered, availableMethods.contains(.publicKey) else {
                failure.value = .authentication
                nextChallengePromise.fail(SSHFailure.authentication)
                return
            }
            offered = true
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(
                username: username, serviceName: "", offer: .privateKey(.init(privateKey: key))))
        }
    }
}

/// The stdin/stdout of a remote command, readable and writable from a non-NIO thread.
final class SSHExecStream: @unchecked Sendable {
    fileprivate var channel: Channel?
    private let condition = NSCondition()
    private var buffer: [UInt8] = []
    private var stderr: [UInt8] = []
    private var finished = false
    private var exitStatus: Int?
    private var _failure: SSHFailure?

    var failure: SSHFailure? { condition.withLock { _failure } }

    /// Blocks until data is available. Returns 0 at end of stream.
    func read(into destination: UnsafeMutableRawBufferPointer) throws(SSHFailure) -> Int {
        condition.lock()
        defer { condition.unlock() }
        while buffer.isEmpty && !finished && _failure == nil {
            condition.wait()
        }
        if let _failure { throw _failure }
        if buffer.isEmpty {
            if let exitStatus, exitStatus != 0 {
                let message = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                throw .remote(message.isEmpty ? "remote command exited with status \(exitStatus)" : message)
            }
            return 0
        }
        let n = min(destination.count, buffer.count)
        buffer.withUnsafeBytes { destination.copyMemory(from: UnsafeRawBufferPointer(rebasing: $0[..<n])) }
        buffer.removeFirst(n)
        return n
    }

    func write(_ bytes: UnsafeRawBufferPointer) throws(SSHFailure) {
        guard let channel else { throw .connection("not connected") }
        if let failure { throw failure }
        var buf = channel.allocator.buffer(capacity: bytes.count)
        buf.writeBytes(bytes)
        do {
            try channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buf))).wait()
        } catch {
            throw failure ?? .connection("write failed: \(error)")
        }
    }

    func close() {
        channel?.close(promise: nil)
    }

    // Called on the event loop:

    fileprivate func receive(_ bytes: ByteBuffer, stderr isStderr: Bool) {
        condition.withLock {
            if isStderr {
                stderr += bytes.readableBytesView
            } else {
                buffer += bytes.readableBytesView
            }
            condition.broadcast()
        }
    }

    fileprivate func receiveExit(_ status: Int) {
        condition.withLock { exitStatus = status }
    }

    fileprivate func finish(_ failure: SSHFailure? = nil) {
        condition.withLock {
            if let failure, _failure == nil { _failure = failure }
            finished = true
            condition.broadcast()
        }
    }
}

private final class ExecHandler: ChannelInboundHandler {
    typealias InboundIn = SSHChannelData
    let stream: SSHExecStream

    init(stream: SSHExecStream) {
        self.stream = stream
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { _ in }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        guard case .byteBuffer(let bytes) = message.data else { return }
        stream.receive(bytes, stderr: message.type == .stdErr)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let status as SSHChannelRequestEvent.ExitStatus:
            stream.receiveExit(status.exitStatus)
        case ChannelEvent.inputClosed:
            stream.finish()
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        stream.finish()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        stream.finish(.connection("\(error)"))
        context.close(promise: nil)
    }
}
