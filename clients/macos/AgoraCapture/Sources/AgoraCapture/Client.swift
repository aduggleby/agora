import Foundation
import Security
import CryptoKit

struct ClientError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
enum Keychain {
    static func read(server: URL) -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "agora.capture", kSecAttrAccount as String: server.absoluteString, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func save(_ token: String, server: URL) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "agora.capture", kSecAttrAccount as String: server.absoluteString]
        let data = Data(token.utf8)
        let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecItemNotFound {
            var insert = query
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            guard SecItemAdd(insert as CFDictionary, nil) == errSecSuccess else { throw ClientError(message: "Could not save credentials in Keychain.") }
        } else if update != errSecSuccess { throw ClientError(message: "Could not update Keychain credentials.") }
    }
    static func remove(server: URL) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "agora.capture", kSecAttrAccount as String: server.absoluteString] as CFDictionary)
    }
}
struct APIError: LocalizedError {
    let status: Int
    let retryAfter: TimeInterval?
    var requiresReconnect: Bool { status == 401 }
    var errorDescription: String? {
        switch status {
        case 400: return "Agora rejected this request. Check the duration and image, then retry."
        case 401: return "Your connection has expired or been revoked. Reconnect in Settings."
        case 404: return "This direct link no longer exists or is not owned by this account."
        case 409: return "This capture was already submitted. Retry with a new upload."
        case 413: return "This image exceeds the server's size limit."
        case 429:
            if let wait = retryAfter { return "Too many requests. Retry in \(Int(ceil(wait))) seconds." }
            return "Your upload quota or request limit has been reached. Please retry later."
        case 503: return "Agora is temporarily busy. Please retry shortly."
        case 507: return "Agora has no temporary storage available. Please retry later."
        default: return "Agora returned HTTP \(status). Please try again."
        }
    }
    static func parse(_ response: HTTPURLResponse, now: Date = Date()) -> APIError {
        var wait: TimeInterval?
        if let header = response.value(forHTTPHeaderField: "Retry-After") {
            if let seconds = Double(header), seconds.isFinite { wait = max(0, seconds) }
            else {
                let formatter = DateFormatter()
                formatter.locale = Locale(identifier: "en_US_POSIX")
                formatter.timeZone = TimeZone(secondsFromGMT: 0)
                formatter.dateFormat = "EEE',' dd MMM yyyy HH':'mm':'ss z"
                if let date = formatter.date(from: header) { wait = max(0, date.timeIntervalSince(now)) }
            }
        }
        if wait == nil && [503, 507].contains(response.statusCode) { wait = 5 }
        return APIError(status: response.statusCode, retryAfter: wait)
    }
}

struct TokenReply: Decodable {
    let accessToken: String
    let tokenType: String
    let tokenID: UUID
    let email: String
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token", tokenType = "token_type", tokenID = "token_id", email
    }
}

struct AgoraClient {
    let server: URL
    let token: String
    var configuration: URLSessionConfiguration = .ephemeral
    var forgetToken: @Sendable (URL) -> Void = { Keychain.remove(server: $0) }

    static func serverURL(_ text: String) throws -> URL {
        guard var c = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              let host = c.host, !host.isEmpty, c.user == nil, c.password == nil, c.query == nil,
              c.fragment == nil, c.path.isEmpty || c.path == "/",
              c.scheme == "https" || (c.scheme == "http" && ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host)),
              c.port == nil || (1...65535).contains(c.port!) else {
            throw ClientError(message: "Enter an HTTPS server address, or HTTP localhost for development.")
        }
        c.path = ""
        guard let url = c.url else { throw ClientError(message: "Enter a valid server address.") }
        return url
    }
    static var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let value = try decoder.singleValueContainer().decode(String.self)
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: value) { return date }
            formatter.formatOptions = [.withInternetDateTime]
            guard let date = formatter.date(from: value) else { throw ClientError(message: "Server returned an invalid expiry date.") }
            return date
        }
        return d
    }
    static func session(configuration: URLSessionConfiguration, delegate: URLSessionDelegate = NoRedirects()) -> URLSession {
        let config = configuration.copy() as! URLSessionConfiguration
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }
    func makeRequest(_ path: String, method: String = "GET") -> URLRequest {
        var request = URLRequest(url: server.appendingPathComponent(path))
        request.httpMethod = method
        request.timeoutInterval = 120
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpShouldHandleCookies = false
        return request
    }
    func validate(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { throw ClientError(message: "No response from Agora.") }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 { forgetToken(server) }
            throw APIError.parse(http)
        }
    }
    func request(_ path: String, method: String = "GET") async throws -> Data {
        let session = Self.session(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: makeRequest(path, method: method))
        try validate(response)
        return data
    }
    func me() async throws -> Account {
        let account = try Self.decoder.decode(Account.self, from: await request("api/v1/me"))
        guard account.maxFileSizeBytes > 0, !account.directLinkDurations.isEmpty,
              account.directLinkDurations.allSatisfy({ !$0.isEmpty }), Set(account.directLinkDurations).count == account.directLinkDurations.count else {
            throw ClientError(message: "Agora returned invalid capture limits. Contact the server administrator.")
        }
        return account
    }
    func revoke() async throws {
        defer { forgetToken(server) }
        _ = try await request("api/v1/auth/token", method: "DELETE")
    }
    func deleteShare(_ token: String) async throws {
        guard token.count == 8, token.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").contains($0) }) else {
            throw ClientError(message: "Invalid direct link identifier.")
        }
        do { _ = try await request("api/v1/shares/\(token)", method: "DELETE") }
        catch let error as APIError where error.status == 404 { return }
    }
    // Multipart envelope is staged on disk, avoiding a second full-size image buffer.
    static func multipartFile(_ png: Data, boundary: String) throws -> URL {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("agora-upload-\(UUID().uuidString).multipart")
        do {
            guard FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw ClientError(message: "Could not stage the image upload.") }
            let handle = try FileHandle(forWritingTo: file)
            defer { try? handle.close() }
            try handle.write(contentsOf: Data("--\(boundary)\r\nContent-Disposition: form-data; name=\"file\"; filename=\"capture.png\"\r\nContent-Type: image/png\r\n\r\n".utf8))
            try handle.write(contentsOf: png)
            try handle.write(contentsOf: Data("\r\n--\(boundary)--\r\n".utf8))
            return file
        } catch { try? FileManager.default.removeItem(at: file); throw error }
    }
    func upload(_ png: Data, duration: String, progress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> UploadReply {
        let boundary = "Agora-\(UUID().uuidString)"
        let file = try Self.multipartFile(png, boundary: boundary)
        defer { try? FileManager.default.removeItem(at: file) }
        var components = URLComponents(url: server, resolvingAgainstBaseURL: false)!
        components.path = "/api/v1/captures"
        components.queryItems = [URLQueryItem(name: "duration", value: duration)]
        var request = makeRequest("api/v1/captures", method: "POST")
        request.url = components.url!
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        let session = Self.session(configuration: configuration, delegate: UploadProgress(progress))
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.upload(for: request, fromFile: file)
        try validate(response)
        let result = try Self.decoder.decode(UploadReply.self, from: data)
        guard ["https", "http"].contains(result.url.scheme), result.url.host != nil, result.url.user == nil, result.url.password == nil,
              result.token.count == 8, result.expiresAtUtc > Date() else { throw ClientError(message: "Agora returned an invalid capture link.") }
        return result
    }
    static func exchange(server: URL, code: String, verifier: String, redirectURI: String, configuration: URLSessionConfiguration = .ephemeral) async throws -> TokenReply {
        var request = URLRequest(url: server.appendingPathComponent("api/v1/auth/token"))
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.httpShouldHandleCookies = false
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["grant_type": "authorization_code", "code": code, "code_verifier": verifier, "redirect_uri": redirectURI, "client_id": "agora-capture"])
        let session = Self.session(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ClientError(message: "No response from Agora.") }
        guard http.statusCode == 200 else {
            if http.statusCode == 400 {
                throw ClientError(message: "Sign-in could not be completed. The code may have expired or already been used. Connect again to start a new sign-in.")
            }
            throw APIError.parse(http)
        }
        let reply = try decoder.decode(TokenReply.self, from: data)
        guard reply.tokenType == "Bearer", reply.accessToken.hasPrefix("agora_pat_"), reply.accessToken.count == 53 else {
            throw ClientError(message: "Agora returned an invalid app token.")
        }
        return reply
    }
}
class NoRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
final class UploadProgress: NoRedirects, @unchecked Sendable {
    let progress: @Sendable (Double) -> Void
    init(_ progress: @escaping @Sendable (Double) -> Void) { self.progress = progress }
    func urlSession(_ session: URLSession, task: URLSessionTask, didSendBodyData bytesSent: Int64, totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
        if totalBytesExpectedToSend > 0 { progress(min(1, Double(totalBytesSent) / Double(totalBytesExpectedToSend))) }
    }
}
enum PKCE {
    static func random(_ count: Int) throws -> String {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { throw ClientError(message: "Could not create secure sign-in state.") }
        return base64(Data(bytes))
    }
    static func base64(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    static func challenge(_ verifier: String) -> String { base64(Data(SHA256.hash(data: Data(verifier.utf8)))) }
}
