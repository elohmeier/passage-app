import Foundation
import NIOCore
import NIOPosix
import NIOSSH

/// A minimal SSH git server for tests: accepts one public key, and runs `git upload-pack` /
/// `git receive-pack` for exec requests.
final class SSHTestServer: @unchecked Sendable {
    let port: Int
    let hostKey: NIOSSHPrivateKey
    private let channel: Channel
    private let group: MultiThreadedEventLoopGroup

    init(authorizedKey: NIOSSHPublicKey) throws {
        // Writing to a git process that already exited must not kill the test runner.
        signal(SIGPIPE, SIG_IGN)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NIOSSHHandler(
                        role: .server(.init(hostKeys: [hostKey], userAuthDelegate: AuthorizedKey(key: authorizedKey))),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: { child, _ in
                            child.eventLoop.makeCompletedFuture {
                                try child.pipeline.syncOperations.addHandler(GitExecHandler())
                            }
                        }))
                }
            }
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        channel = try bootstrap.bind(host: "127.0.0.1", port: 0).wait()
        port = channel.localAddress!.port!
        self.hostKey = hostKey
        self.group = group
    }

    func stop() {
        try? channel.close().wait()
        try? group.syncShutdownGracefully()
    }

    private final class AuthorizedKey: NIOSSHServerUserAuthenticationDelegate {
        let key: NIOSSHPublicKey
        init(key: NIOSSHPublicKey) { self.key = key }

        var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods { .publicKey }

        func requestReceived(
            request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
        ) {
            guard case .publicKey(let offered) = request.request, offered.publicKey == key else {
                responsePromise.succeed(.failure)
                return
            }
            responsePromise.succeed(.success)
        }
    }
}

/// Runs `git-upload-pack '<path>'` (or receive-pack) and pipes it through the SSH channel.
private final class GitExecHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData

    private var process: Process?
    private var stdin: FileHandle?

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { _ in }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let exec as SSHChannelRequestEvent.ExecRequest:
            if exec.wantReply { context.triggerUserOutboundEvent(ChannelSuccessEvent(), promise: nil) }
            start(exec.command, context: context)
        case ChannelEvent.inputClosed:
            try? stdin?.close()
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard case .byteBuffer(let bytes) = unwrapInboundIn(data).data else { return }
        try? stdin?.write(contentsOf: Data(bytes.readableBytesView))
    }

    private func start(_ command: String, context: ChannelHandlerContext) {
        // "git-upload-pack '/path'" → git upload-pack /path
        let parts = command.split(separator: " ", maxSplits: 1).map(String.init)
        guard parts.count == 2, parts[0].hasPrefix("git-") else {
            context.close(promise: nil)
            return
        }
        let path = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "'"))
        let p = Process()
        p.executableURL = URL(filePath: "/usr/bin/git")
        p.arguments = [String(parts[0].dropFirst(4)), path]
        let input = Pipe(), output = Pipe()
        p.standardInput = input
        p.standardOutput = output
        p.standardError = FileHandle.nullDevice
        stdin = input.fileHandleForWriting
        process = p

        let loop = context.eventLoop
        let bound = NIOLoopBound(context, eventLoop: loop)
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                p.waitUntilExit()
                let status = Int(p.terminationStatus)
                loop.execute {
                    let context = bound.value
                    context.triggerUserOutboundEvent(SSHChannelRequestEvent.ExitStatus(exitStatus: status), promise: nil)
                    context.close(promise: nil)
                }
                return
            }
            loop.execute {
                let context = bound.value
                var buffer = context.channel.allocator.buffer(capacity: data.count)
                buffer.writeBytes(data)
                context.writeAndFlush(NIOAny(SSHChannelData(type: .channel, data: .byteBuffer(buffer))), promise: nil)
            }
        }
        do {
            try p.run()
        } catch {
            context.close(promise: nil)
        }
    }
}
