import Foundation

public enum GitHubError: Error, Equatable, Sendable, LocalizedError {
    case deviceFlowDisabled
    case accessDenied
    case expired
    case http(status: Int, message: String)
    case decoding(String)
    case unexpected(String)

    public var errorDescription: String? {
        switch self {
        case .deviceFlowDisabled: "Device flow isn't enabled for this GitHub App."
        case .accessDenied: "Access was denied on GitHub."
        case .expired: "The code expired. Start again."
        case .http(let status, let message): "GitHub returned \(status): \(message)"
        case .decoding(let m): "Unexpected response from GitHub: \(m)"
        case .unexpected(let m): m
        }
    }
}

/// OAuth device flow for a GitHub App (https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app#using-the-device-flow-to-generate-a-user-access-token).
/// Needs only the public client ID: no client secret ships in the app.
public struct DeviceFlow: Sendable {
    public struct Code: Sendable, Equatable, Decodable {
        public let deviceCode: String
        /// What the user types at `verificationURI`, e.g. `WDJB-MJHT`.
        public let userCode: String
        public let verificationURI: URL
        public let expiresIn: Int
        public let interval: Int

        public init(deviceCode: String, userCode: String, verificationURI: URL, expiresIn: Int, interval: Int) {
            self.deviceCode = deviceCode
            self.userCode = userCode
            self.verificationURI = verificationURI
            self.expiresIn = expiresIn
            self.interval = interval
        }

        enum CodingKeys: String, CodingKey {
            case deviceCode = "device_code", userCode = "user_code", verificationURI = "verification_uri"
            case expiresIn = "expires_in", interval
        }
    }

    public let clientID: String
    let session: URLSession
    let sleep: @Sendable (Duration) async throws -> Void

    public init(
        clientID: String, session: URLSession = .shared,
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }
    ) {
        self.clientID = clientID
        self.session = session
        self.sleep = sleep
    }

    public func requestCode() async throws -> Code {
        // Errors such as device_flow_disabled arrive as 200 responses with an "error" field.
        let data = try await post("https://github.com/login/device/code", ["client_id": clientID])
        if let error = try? JSONDecoder().decode(TokenResponse.self, from: data), let code = error.error {
            throw code == "device_flow_disabled" ? GitHubError.deviceFlowDisabled : GitHubError.unexpected(error.errorDescription ?? code)
        }
        return try decode(Code.self, data)
    }

    /// Polls until the user approves (returns the access token), denies, or the code expires.
    public func waitForToken(_ code: Code) async throws -> String {
        var interval = max(code.interval, 1)
        let deadline = ContinuousClock.now + .seconds(code.expiresIn)
        while ContinuousClock.now < deadline {
            try await sleep(.seconds(interval))
            let response = try decode(TokenResponse.self, try await post(
                "https://github.com/login/oauth/access_token",
                ["client_id": clientID, "device_code": code.deviceCode, "grant_type": "urn:ietf:params:oauth:grant-type:device_code"]))
            if let token = response.accessToken { return token }
            switch response.error {
            case "authorization_pending": continue
            case "slow_down": interval = response.interval ?? interval + 5
            case "expired_token": throw GitHubError.expired
            case "access_denied": throw GitHubError.accessDenied
            case "device_flow_disabled": throw GitHubError.deviceFlowDisabled
            default: throw GitHubError.unexpected(response.errorDescription ?? response.error ?? "unknown error")
            }
        }
        throw GitHubError.expired
    }

    struct TokenResponse: Decodable {
        let accessToken: String?
        let error: String?
        let errorDescription: String?
        let interval: Int?

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token", error, errorDescription = "error_description", interval
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw GitHubError.decoding("\(error)")
        }
    }

    private func post(_ url: String, _ form: [String: String]) async throws -> Data {
        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var components = URLComponents()
        components.queryItems = form.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        request.httpBody = Data((components.percentEncodedQuery ?? "").utf8)
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw GitHubError.http(status: status, message: String(decoding: data.prefix(200), as: UTF8.self))
        }
        return data
    }
}
