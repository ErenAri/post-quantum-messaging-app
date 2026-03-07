import Foundation

enum ApiClientError: Error {
    case invalidURL(String)
    case transportPolicy(String)
    case requestFailed(Int, String)
}

final class ApiClient {
    private let baseURL: URL
    private let session: URLSession

    init(serverURL: String) throws {
        self.baseURL = try ApiClient.normalizeBaseURL(serverURL)
        self.session = URLSession(configuration: .default)
    }

    func pingRoot() async throws {
        _ = try await requestData(path: "", method: "GET", headers: [:], body: Optional<String>.none)
    }

    func getCapabilities() async throws -> ServerCapabilitiesResponse {
        try await request(path: "v1/capabilities", method: "GET", headers: [:], body: Optional<String>.none)
    }

    func registerUser(_ requestBody: RegisterUserRequest) async throws -> RegisterUserResponse {
        try await request(path: "v1/users/register", method: "POST", headers: [:], body: requestBody)
    }

    func publishPrekeys(userId: String, requestBody: PublishPrekeysRequest, headers: [String: String]) async throws -> PublishPrekeysResponse {
        try await request(path: "v1/users/\(userId)/prekeys", method: "POST", headers: headers, body: requestBody)
    }

    func getBundle(userId: String) async throws -> BundleResponse {
        try await request(path: "v1/users/\(userId)/bundle", method: "GET", headers: [:], body: Optional<String>.none)
    }

    func relay(recipientUserId: String, headers: [String: String], requestBody: RelayRequest) async throws -> RelayResponse {
        try await request(path: "v1/relay/\(recipientUserId)", method: "POST", headers: headers, body: requestBody)
    }

    func inbox(userId: String, since: Int64, headers: [String: String]) async throws -> InboxResponse {
        try await request(
            path: "v1/inbox/\(userId)?since=\(since)",
            method: "GET",
            headers: headers,
            body: Optional<String>.none
        )
    }

    func registerPushToken(userId: String, headers: [String: String], requestBody: RegisterPushTokenRequest) async throws -> RegisterPushTokenResponse {
        try await request(path: "v1/users/\(userId)/push-token", method: "POST", headers: headers, body: requestBody)
    }

    func listDevices(userId: String, headers: [String: String]) async throws -> DeviceListResponse {
        try await request(
            path: "v1/users/\(userId)/devices",
            method: "GET",
            headers: headers,
            body: Optional<String>.none
        )
    }

    func linkDevice(userId: String, newDeviceId: String, headers: [String: String]) async throws -> LinkDeviceResponse {
        try await request(
            path: "v1/users/\(userId)/devices/link",
            method: "POST",
            headers: headers,
            body: ["new_device_id": newDeviceId]
        )
    }

    func revokeDevice(userId: String, targetDeviceId: String, headers: [String: String]) async throws -> RevokeDeviceResponse {
        try await request(
            path: "v1/users/\(userId)/devices/\(targetDeviceId)/revoke",
            method: "POST",
            headers: headers,
            body: Optional<String>.none
        )
    }

    func retireCurrentDevice(userId: String, headers: [String: String]) async throws -> RetireCurrentDeviceResponse {
        try await request(
            path: "v1/users/\(userId)/devices/current/retire",
            method: "POST",
            headers: headers,
            body: Optional<String>.none
        )
    }

    func rotateInit(
        userId: String,
        headers: [String: String],
        requestBody: RotateInitRequest
    ) async throws -> RotateInitResponse {
        try await request(
            path: "v1/users/\(userId)/rotate/init",
            method: "POST",
            headers: headers,
            body: requestBody
        )
    }

    func rotateConfirm(
        userId: String,
        headers: [String: String],
        requestBody: RotateConfirmRequest
    ) async throws -> RotateConfirmResponse {
        try await request(
            path: "v1/users/\(userId)/rotate/confirm",
            method: "POST",
            headers: headers,
            body: requestBody
        )
    }

    func identityLog(userId: String, headers: [String: String]) async throws -> IdentityLogResponse {
        try await request(
            path: "v1/users/\(userId)/identity-log",
            method: "GET",
            headers: headers,
            body: Optional<String>.none
        )
    }

    private func request<T: Decodable, U: Encodable>(
        path: String,
        method: String,
        headers: [String: String],
        body: U?
    ) async throws -> T {
        let data = try await requestData(path: path, method: method, headers: headers, body: body)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func requestData<U: Encodable>(
        path: String,
        method: String,
        headers: [String: String],
        body: U?
    ) async throws -> Data {
        let url = try endpointURL(path: path)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        headers.forEach { key, value in
            request.setValue(value, forHTTPHeaderField: key)
        }
        if let body {
            request.httpBody = try JSONEncoder().encode(body)
        }

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ApiClientError.requestFailed(-1, "invalid HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let bodyText = String(data: data, encoding: .utf8) ?? "<non-utf8>"
            throw ApiClientError.requestFailed(http.statusCode, bodyText)
        }
        return data
    }

    private func endpointURL(path: String) throws -> URL {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return baseURL
        }
        if let queryIndex = trimmed.firstIndex(of: "?") {
            let basePath = String(trimmed[..<queryIndex])
            let query = String(trimmed[trimmed.index(after: queryIndex)...])
            guard var components = URLComponents(url: baseURL.appendingPathComponent(basePath), resolvingAgainstBaseURL: false) else {
                throw ApiClientError.invalidURL("unable to construct endpoint URL")
            }
            components.percentEncodedQuery = query
            guard let url = components.url else {
                throw ApiClientError.invalidURL("unable to encode endpoint query")
            }
            return url
        }
        return baseURL.appendingPathComponent(trimmed)
    }

    private static func normalizeBaseURL(_ raw: String) throws -> URL {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw ApiClientError.invalidURL("server URL is empty")
        }
        let normalized = trimmed.hasSuffix("/") ? trimmed : "\(trimmed)/"
        guard let url = URL(string: normalized),
              let scheme = url.scheme,
              let host = url.host
        else {
            throw ApiClientError.invalidURL("server URL is invalid")
        }
        if scheme == "http" {
            #if DEBUG
            guard host == "127.0.0.1" || host == "localhost" || host == "10.0.2.2" else {
                throw ApiClientError.transportPolicy("HTTP is only allowed for local debug hosts")
            }
            #else
            throw ApiClientError.transportPolicy("HTTP is not allowed in release builds")
            #endif
        } else if scheme != "https" {
            throw ApiClientError.invalidURL("server URL scheme must be http or https")
        }
        return url
    }
}
