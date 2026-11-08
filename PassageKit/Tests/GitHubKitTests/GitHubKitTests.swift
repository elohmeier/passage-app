import Foundation
import Synchronization
import Testing

@testable import GitHubKit

/// Serves canned responses in order per "METHOD path", and records requests.
final class StubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responses: [String: [(Int, String)]] = [:]
    nonisolated(unsafe) static var requests: [URLRequest] = []
    static let lock = NSLock()

    static func reset(_ r: [String: [(Int, String)]]) {
        lock.withLock {
            responses = r
            requests = []
        }
    }

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: config)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var request = self.request
        if request.httpBody == nil, let stream = request.httpBodyStream {
            stream.open()
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                data.append(buffer, count: n)
            }
            request.httpBody = data
        }
        let key = "\(request.httpMethod ?? "GET") \(request.url!.path)"
        let (status, body) = Self.lock.withLock { () -> (Int, String) in
            Self.requests.append(request)
            guard var queue = Self.responses[key], !queue.isEmpty else { return (599, "no stub for \(key)") }
            let next = queue.removeFirst()
            Self.responses[key] = queue.isEmpty ? [next] : queue
            return next
        }
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// Both suites share StubProtocol's global state, so they must not run in parallel.
@Suite(.serialized) struct GitHubKitTests {
    @Suite struct DeviceFlowTests {
        let flow = DeviceFlow(clientID: "Iv1.test", session: StubProtocol.session(), sleep: { _ in })

        @Test func pollsUntilApproved() async throws {
            StubProtocol.reset([
                "POST /login/device/code": [(200, #"{"device_code":"dc","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#)],
                "POST /login/oauth/access_token": [
                    (200, #"{"error":"authorization_pending"}"#),
                    (200, #"{"error":"slow_down","interval":10}"#),
                    (200, #"{"access_token":"ghu_123","token_type":"bearer"}"#),
                ],
            ])
            let code = try await flow.requestCode()
            #expect(code.userCode == "WDJB-MJHT")
            #expect(try await flow.waitForToken(code) == "ghu_123")

            let bodies = StubProtocol.requests.compactMap { $0.httpBody.map { String(decoding: $0, as: UTF8.self) } }
            #expect(bodies.first == "client_id=Iv1.test")
            #expect(bodies.last == "client_id=Iv1.test&device_code=dc&grant_type=urn:ietf:params:oauth:grant-type:device_code")
            #expect(!bodies.contains { $0.contains("secret") })
        }

        @Test func denied() async throws {
            StubProtocol.reset(["POST /login/oauth/access_token": [(200, #"{"error":"access_denied"}"#)]])
            let code = DeviceFlow.Code(deviceCode: "dc", userCode: "X", verificationURI: URL(string: "https://github.com/login/device")!, expiresIn: 900, interval: 5)
            await #expect(throws: GitHubError.accessDenied) { try await flow.waitForToken(code) }
        }

        @Test func deviceFlowDisabled() async throws {
            StubProtocol.reset(["POST /login/oauth/access_token": [(200, #"{"error":"device_flow_disabled"}"#)]])
            let code = DeviceFlow.Code(deviceCode: "dc", userCode: "X", verificationURI: URL(string: "https://github.com/login/device")!, expiresIn: 900, interval: 5)
            await #expect(throws: GitHubError.deviceFlowDisabled) { try await flow.waitForToken(code) }
        }
    }

    @Suite struct GitHubAPITests {
        let api = GitHubAPI(token: "ghu_123", session: StubProtocol.session())

        static func repo(_ id: Int, _ name: String, private: Bool = true) -> String {
            #"{"id":\#(id),"name":"\#(name)","full_name":"alice/\#(name)","private":\#(`private`),"ssh_url":"git@github.com:alice/\#(name).git","default_branch":"main","pushed_at":"2026-11-01T10:00:00Z"}"#
        }

        @Test func installationsAndPagedRepositories() async throws {
            StubProtocol.reset([
                "GET /user/installations": [(200, #"{"total_count":1,"installations":[{"id":7,"account":{"login":"alice"}}]}"#)],
                "GET /user/installations/7/repositories": [
                    (200, #"{"total_count":3,"repositories":[\#(Self.repo(1, "pass")),\#(Self.repo(2, "blog", private: false))]}"#),
                    (200, #"{"total_count":3,"repositories":[\#(Self.repo(3, "dotfiles"))]}"#),
                ],
            ])
            let installations = try await api.installations()
            #expect(installations.map(\.account.login) == ["alice"])
            let repos = try await api.repositories(installation: 7)
            #expect(repos.map(\.name) == ["pass", "blog", "dotfiles"])
            #expect(repos[0].sshURL == "git@github.com:alice/pass.git")
            #expect(repos[1].private == false)
            #expect(repos[0].owner == "alice")

            let auth = StubProtocol.requests.first?.value(forHTTPHeaderField: "Authorization")
            #expect(auth == "Bearer ghu_123")
            #expect(StubProtocol.requests.first?.value(forHTTPHeaderField: "X-GitHub-Api-Version") == "2022-11-28")
        }

        @Test func fileExists() async throws {
            let repo = GitHubAPI.Repository(id: 1, name: "pass", fullName: "alice/pass", private: true, sshURL: "", defaultBranch: "main", pushedAt: nil)
            StubProtocol.reset(["GET /repos/alice/pass/contents/.age-recipients": [(200, #"{"type":"file"}"#)]])
            #expect(try await api.fileExists(".age-recipients", in: repo))
            StubProtocol.reset(["GET /repos/alice/pass/contents/.age-recipients": [(404, #"{"message":"Not Found"}"#)]])
            #expect(try await !api.fileExists(".age-recipients", in: repo))
        }

        @Test func deployKey() async throws {
            let repo = GitHubAPI.Repository(id: 1, name: "pass", fullName: "alice/pass", private: true, sshURL: "", defaultBranch: "main", pushedAt: nil)
            StubProtocol.reset([
                "POST /repos/alice/pass/keys": [(201, #"{"id":42,"title":"Passage on iPhone","key":"ecdsa-sha2-nistp256 AAAA"}"#)],
                "DELETE /repos/alice/pass/keys/42": [(204, "")],
            ])
            let key = try await api.addDeployKey(to: repo, title: "Passage on iPhone", key: "ecdsa-sha2-nistp256 AAAA")
            #expect(key.id == 42)
            let body = try JSONSerialization.jsonObject(with: StubProtocol.requests[0].httpBody!) as! [String: Any]
            #expect(body["read_only"] as? Bool == false)
            #expect(body["title"] as? String == "Passage on iPhone")
            try await api.deleteDeployKey(42, from: "alice/pass")
        }

        @Test func errorsCarryGitHubMessage() async throws {
            let repo = GitHubAPI.Repository(id: 1, name: "pass", fullName: "alice/pass", private: true, sshURL: "", defaultBranch: "main", pushedAt: nil)
            StubProtocol.reset(["POST /repos/alice/pass/keys": [(422, #"{"message":"key is already in use"}"#)]])
            await #expect(throws: GitHubError.http(status: 422, message: "key is already in use")) {
                try await api.addDeployKey(to: repo, title: "x", key: "y")
            }
        }
    }
}
