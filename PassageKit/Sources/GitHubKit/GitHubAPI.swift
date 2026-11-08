import Foundation

/// The few REST endpoints the setup flow needs, with a user access token from `DeviceFlow`.
public struct GitHubAPI: Sendable {
    public struct User: Decodable, Sendable, Equatable {
        public let login: String
    }

    public struct Installation: Decodable, Sendable, Equatable, Identifiable {
        public let id: Int
        public let account: User
    }

    public struct Repository: Decodable, Sendable, Equatable, Identifiable, Hashable {
        public let id: Int
        public let name: String
        public let fullName: String
        public let `private`: Bool
        public let sshURL: String
        public let defaultBranch: String
        public let pushedAt: Date?

        enum CodingKeys: String, CodingKey {
            case id, name, `private`, fullName = "full_name", sshURL = "ssh_url", defaultBranch = "default_branch"
            case pushedAt = "pushed_at"
        }

        public init(id: Int, name: String, fullName: String, private: Bool, sshURL: String, defaultBranch: String, pushedAt: Date?) {
            self.id = id
            self.name = name
            self.fullName = fullName
            self.private = `private`
            self.sshURL = sshURL
            self.defaultBranch = defaultBranch
            self.pushedAt = pushedAt
        }

        public var owner: String { String(fullName.split(separator: "/").first ?? "") }
    }

    public struct DeployKey: Decodable, Sendable, Equatable {
        public let id: Int
        public let title: String
    }

    let token: String
    let session: URLSession
    let base: URL

    public init(token: String, session: URLSession = .gitHub, base: URL = URL(string: "https://api.github.com")!) {
        self.token = token
        self.session = session
        self.base = base
    }

    public func user() async throws -> User {
        try await get("user")
    }

    public func installations() async throws -> [Installation] {
        struct Page: Decodable { let installations: [Installation] }
        let page: Page = try await get("user/installations", query: ["per_page": "100"])
        return page.installations
    }

    /// Repositories of an installation that the user can access.
    public func repositories(installation: Int) async throws -> [Repository] {
        struct Page: Decodable {
            let totalCount: Int
            let repositories: [Repository]
            enum CodingKeys: String, CodingKey { case totalCount = "total_count", repositories }
        }
        var all: [Repository] = []
        var page = 1
        while true {
            let p: Page = try await get("user/installations/\(installation)/repositories", query: ["per_page": "100", "page": "\(page)"])
            all += p.repositories
            if all.count >= p.totalCount || p.repositories.isEmpty { return all }
            page += 1
        }
    }

    /// True if `path` exists in the repository (default branch).
    public func fileExists(_ path: String, in repo: Repository) async throws -> Bool {
        do {
            let _: EmptyResponse = try await get("repos/\(repo.fullName)/contents/\(path)")
            return true
        } catch GitHubError.http(status: 404, _) {
            return false
        }
    }

    /// Adds a read/write deploy key. Requires the app's "Administration: write" permission.
    public func addDeployKey(to repo: Repository, title: String, key: String) async throws -> DeployKey {
        struct NewKey: Encodable {
            let title: String
            let key: String
            let read_only = false
        }
        return try await send("POST", "repos/\(repo.fullName)/keys", body: NewKey(title: title, key: key))
    }

    public func deleteDeployKey(_ id: Int, from fullName: String) async throws {
        let _: EmptyResponse = try await send("DELETE", "repos/\(fullName)/keys/\(id)", body: nil as String?)
    }

    // MARK: Plumbing

    struct EmptyResponse: Decodable {}
    struct ErrorMessage: Decodable { let message: String }

    private func get<T: Decodable>(_ path: String, query: [String: String] = [:]) async throws -> T {
        try await send("GET", path, query: query, body: nil as String?)
    }

    private func send<T: Decodable, Body: Encodable>(
        _ method: String, _ path: String, query: [String: String] = [:], body: Body?
    ) async throws -> T {
        var components = URLComponents(url: base.appending(path: path), resolvingAgainstBaseURL: false)!
        if !query.isEmpty { components.queryItems = query.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) } }
        var request = URLRequest(url: components.url!)
        request.httpMethod = method
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(body)
        }
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let message = (try? JSONDecoder().decode(ErrorMessage.self, from: data))?.message ?? String(decoding: data.prefix(200), as: UTF8.self)
            throw GitHubError.http(status: status, message: message)
        }
        if T.self == EmptyResponse.self { return EmptyResponse() as! T }
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(T.self, from: data)
        } catch {
            throw GitHubError.decoding("\(error)")
        }
    }
}
