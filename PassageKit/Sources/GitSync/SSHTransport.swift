import CGit2
import Foundation
import NIOSSH

/// libgit2 smart subtransport for `ssh://` and scp-style (`git@host:path`) URLs, running
/// `git-upload-pack` / `git-receive-pack` over swift-nio-ssh.
///
/// libgit2 builds without SSH support on iOS (it can't spawn `ssh`), so we register this in its
/// place. Per-operation state (key, known hosts) comes from the remote callbacks' payload, the
/// same `CallbackContext` that HTTPS credentials use.
enum SSHTransport {
    static let registered: Void = {
        let definition = UnsafeMutablePointer<git_smart_subtransport_definition>.allocate(capacity: 1)
        definition.initialize(to: git_smart_subtransport_definition(callback: { out, owner, param in makeSubtransport(out, owner, param) }, rpc: 0, param: nil))
        // libgit2 appends "://" to the scheme (despite git2/sys/transport.h saying "git://").
        for prefix in ["ssh", "ssh+git", "git+ssh"] {
            let code = git_transport_register(prefix, { out, owner, param in git_transport_smart(out, owner, param) }, definition)
            precondition(code == 0, "git_transport_register(\(prefix)) failed")
        }
    }()

    /// libgit2 holds a `git_smart_subtransport *`; we allocate it with room for a pointer to our
    /// Swift state right after it, and find the state again from the C struct pointer.
    private static func makeSubtransport(
        _ out: UnsafeMutablePointer<UnsafeMutablePointer<git_smart_subtransport>?>?, _ owner: UnsafeMutablePointer<git_transport>?,
        _ param: UnsafeMutableRawPointer?
    ) -> Int32 {
        let state = Subtransport(owner: owner!)
        let raw = Embedded<git_smart_subtransport>.allocate(context: state)
        raw.pointee.action = { out, transport, url, action in
            Embedded<git_smart_subtransport>.context(of: transport!, as: Subtransport.self).action(out!, url: String(cString: url!), service: action)
        }
        raw.pointee.close = { transport in
            Embedded<git_smart_subtransport>.context(of: transport!, as: Subtransport.self).close()
            return 0
        }
        raw.pointee.free = { transport in
            Embedded<git_smart_subtransport>.context(of: transport!, as: Subtransport.self).close()
            Embedded<git_smart_subtransport>.free(transport!)
        }
        out!.pointee = raw
        return 0
    }

    /// One transport instance; one SSH connection per fetch or push.
    private final class Subtransport {
        let owner: UnsafeMutablePointer<git_transport>
        var connection: SSHConnection?
        var stream: UnsafeMutablePointer<git_smart_subtransport_stream>?

        init(owner: UnsafeMutablePointer<git_transport>) {
            self.owner = owner
        }

        func action(
            _ out: UnsafeMutablePointer<UnsafeMutablePointer<git_smart_subtransport_stream>?>, url: String,
            service: git_smart_service_t
        ) -> Int32 {
            switch service {
            case GIT_SERVICE_UPLOADPACK_LS, GIT_SERVICE_RECEIVEPACK_LS:
                close()
                let command = service == GIT_SERVICE_UPLOADPACK_LS ? "git-upload-pack" : "git-receive-pack"
                do {
                    let exec = try connect(url: url, command: command)
                    stream = Self.makeStream(exec)
                } catch {
                    return fail(error)
                }
            case GIT_SERVICE_UPLOADPACK, GIT_SERVICE_RECEIVEPACK:
                // The *_LS action already started the command; git's ssh protocol continues on
                // the same stream.
                guard stream != nil else { return fail(SSHFailure.connection("no active stream")) }
            default:
                return fail(SSHFailure.connection("invalid service"))
            }
            out.pointee = stream
            return 0
        }

        func close() {
            if let stream {
                Embedded<git_smart_subtransport_stream>.context(of: stream, as: SSHExecStream.self).close()
                Embedded<git_smart_subtransport_stream>.free(stream)
                self.stream = nil
            }
            connection?.close()
            connection = nil
        }

        private func connect(url: String, command: String) throws -> SSHExecStream {
            guard let target = SSHURL(url) else { throw SSHFailure.connection("invalid SSH URL: \(url)") }
            let context = try callbackContext()
            guard case .ssh(let configuredUser, let key) = context.credentials else {
                throw SSHFailure.authentication
            }
            let username = target.user ?? configuredUser ?? "git"
            let hostID = target.port == 22 ? target.host : "[\(target.host)]:\(target.port)"
            let knownHosts = context.knownHosts

            let connection = try SSHConnection.connect(
                host: target.host, port: target.port, username: username, key: try key.privateKey()
            ) { hostKey in
                let presented = HostKey(host: hostID, key: hostKey)
                let status = knownHosts.status(of: presented)
                return status == .trusted ? nil : .hostKey(presented, status)
            }
            self.connection = connection
            return try connection.exec("\(command) \(Self.shellQuote(target.path))")
        }

        /// The `CallbackContext` of the running fetch/push, via the remote callbacks' payload.
        private func callbackContext() throws -> CallbackContext {
            var options = git_remote_connect_options()
            git_remote_connect_options_init(&options, UInt32(GIT_REMOTE_CONNECT_OPTIONS_VERSION))
            defer { git_remote_connect_options_dispose(&options) }
            guard git_transport_remote_connect_options(&options, owner) == 0, let payload = options.callbacks.payload else {
                throw SSHFailure.connection("missing transport context")
            }
            return Unmanaged<CallbackContext>.fromOpaque(payload).takeUnretainedValue()
        }

        /// Records the failure for `GitRepo` to turn into a typed error, and tells libgit2.
        private func fail(_ error: any Error) -> Int32 {
            let failure = (error as? SSHFailure) ?? .connection("\(error)")
            if let context = try? callbackContext() { context.sshFailure = failure }
            git_error_set_str(Int32(GIT_ERROR_SSH.rawValue), "\(failure)")
            return -1
        }

        static func makeStream(_ exec: SSHExecStream) -> UnsafeMutablePointer<git_smart_subtransport_stream> {
            let raw = Embedded<git_smart_subtransport_stream>.allocate(context: exec)
            raw.pointee.read = { stream, buffer, size, bytesRead in
                let exec = Embedded<git_smart_subtransport_stream>.context(of: stream!, as: SSHExecStream.self)
                do {
                    bytesRead!.pointee = try exec.read(into: UnsafeMutableRawBufferPointer(start: buffer, count: size))
                    return 0
                } catch {
                    git_error_set_str(Int32(GIT_ERROR_SSH.rawValue), "\(error)")
                    return -1
                }
            }
            raw.pointee.write = { stream, buffer, length in
                let exec = Embedded<git_smart_subtransport_stream>.context(of: stream!, as: SSHExecStream.self)
                do {
                    try exec.write(UnsafeRawBufferPointer(start: buffer, count: length))
                    return 0
                } catch {
                    git_error_set_str(Int32(GIT_ERROR_SSH.rawValue), "\(error)")
                    return -1
                }
            }
            // The subtransport owns streams and frees them in close().
            raw.pointee.free = { _ in }
            return raw
        }

        /// Single-quotes for the remote shell, as git does.
        static func shellQuote(_ s: String) -> String {
            "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }
    }
}

/// `ssh://[user@]host[:port]/path` or scp-style `[user@]host:path`.
struct SSHURL: Equatable {
    init(user: String?, host: String, port: Int, path: String) {
        self.user = user
        self.host = host
        self.port = port
        self.path = path
    }

    var user: String?
    var host: String
    var port: Int
    var path: String

    init?(_ url: String) {
        if let schemeEnd = url.range(of: "://") {
            guard let c = URLComponents(string: "ssh" + url[schemeEnd.lowerBound...]), let host = c.host, !host.isEmpty else {
                return nil
            }
            user = c.user
            self.host = host
            port = c.port ?? 22
            // ssh://host/~/repo means a path relative to the home directory, like git.
            path = c.path.hasPrefix("/~") ? String(c.path.dropFirst()) : c.path
        } else {
            guard let colon = url.firstIndex(of: ":") else { return nil }
            let hostPart = url[..<colon]
            if let at = hostPart.lastIndex(of: "@") {
                user = String(hostPart[..<at])
                host = String(hostPart[hostPart.index(after: at)...])
            } else {
                host = String(hostPart)
            }
            port = 22
            path = String(url[url.index(after: colon)...])
        }
        guard !host.isEmpty, !path.isEmpty else { return nil }
    }
}

/// A C struct followed by a pointer to a retained Swift object, so C callbacks that only
/// receive the struct pointer can find their Swift state.
enum Embedded<C> {
    private static var contextOffset: Int {
        let stride = MemoryLayout<C>.stride
        let align = MemoryLayout<UnsafeRawPointer>.alignment
        return (stride + align - 1) / align * align
    }

    static func allocate(context: AnyObject) -> UnsafeMutablePointer<C> {
        let raw = UnsafeMutableRawPointer.allocate(
            byteCount: contextOffset + MemoryLayout<UnsafeRawPointer>.size,
            alignment: max(MemoryLayout<C>.alignment, MemoryLayout<UnsafeRawPointer>.alignment))
        raw.initializeMemory(as: UInt8.self, repeating: 0, count: contextOffset)
        raw.storeBytes(of: Unmanaged.passRetained(context).toOpaque(), toByteOffset: contextOffset, as: UnsafeMutableRawPointer.self)
        return raw.bindMemory(to: C.self, capacity: 1)
    }

    static func context<T: AnyObject>(of pointer: UnsafeMutablePointer<C>, as: T.Type) -> T {
        let opaque = UnsafeRawPointer(pointer).load(fromByteOffset: contextOffset, as: UnsafeMutableRawPointer.self)
        return Unmanaged<T>.fromOpaque(opaque).takeUnretainedValue()
    }

    static func free(_ pointer: UnsafeMutablePointer<C>) {
        let raw = UnsafeMutableRawPointer(pointer)
        Unmanaged<AnyObject>.fromOpaque(raw.load(fromByteOffset: contextOffset, as: UnsafeMutableRawPointer.self)).release()
        raw.deallocate()
    }
}
