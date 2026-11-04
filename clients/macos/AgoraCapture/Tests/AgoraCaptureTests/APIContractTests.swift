import XCTest
@testable import AgoraCapture

private final class StubProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, [String: String], Data))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let (status, headers, data) = try Self.handler!(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
private final class ForgetSpy: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [URL] = []
    func record(_ url: URL) { lock.lock(); defer { lock.unlock() }; stored.append(url) }
    var urls: [URL] { lock.lock(); defer { lock.unlock() }; return stored }
}
final class APIContractTests: XCTestCase {
    let server = URL(string: "https://contract-test.invalid")!
    let token = "agora_pat_" + String(repeating: "a", count: 43)
    var config: URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return config
    }
    var client: AgoraClient { AgoraClient(server: server, token: token, configuration: config, forgetToken: { _ in }) }
    override func tearDown() { StubProtocol.handler = nil; super.tearDown() }
    func testMeUsesBearerAndServerProvidedDurations() async throws {
        StubProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/api/v1/me")
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), self.token.prependingBearer)
            XCTAssertFalse(request.httpShouldHandleCookies)
            XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
            return (200, [:], Data(#"{"email":"alex@example.com","displayName":"Alex","serverVersion":"0.10.0","maxFileSizeBytes":100000,"directLinkDurations":["6h","1d"]}"#.utf8))
        }
        let account = try await client.me()
        XCTAssertEqual(account.directLinkDurations, ["6h", "1d"])
        XCTAssertEqual(account.maxFileSizeBytes, 100000)
    }
    func testUnauthorizedForgetsCredentialsAndRequiresReconnect() async {
        let spy = ForgetSpy()
        let client = AgoraClient(server: server, token: token, configuration: config, forgetToken: { spy.record($0) })
        StubProtocol.handler = { _ in (401, ["WWW-Authenticate": "Bearer error=\"invalid_token\""], Data(#"{"error":"revoked"}"#.utf8)) }
        do { _ = try await client.me(); XCTFail("Expected 401") }
        catch let error as APIError { XCTAssertTrue(error.requiresReconnect) }
        catch { XCTFail("Unexpected error: \(error)") }
        XCTAssertEqual(spy.urls, [server])
    }
    func testDeleteAccepts204And404WithoutComparingMessageText() async throws {
        for status in [204, 404] {
            StubProtocol.handler = { request in
                XCTAssertEqual(request.httpMethod, "DELETE")
                XCTAssertEqual(request.url?.path, "/api/v1/shares/Ab3dE6gH")
                return (status, [:], Data(#"{"error":"localized or changed server text"}"#.utf8))
            }
            try await client.deleteShare("Ab3dE6gH")
        }
    }
    func testDeleteRejectsPathInjectionBeforeNetwork() async {
        StubProtocol.handler = { _ in XCTFail("Must not reach network"); return (204, [:], Data()) }
        do { try await client.deleteShare("../token"); XCTFail("Expected invalid identifier") } catch {}
    }
    func testDisconnectAlwaysForgetsTokenIncludingNetworkFailure() async {
        let spy = ForgetSpy()
        let client = AgoraClient(server: server, token: token, configuration: config, forgetToken: { spy.record($0) })
        StubProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/api/v1/auth/token")
            XCTAssertEqual(request.httpMethod, "DELETE")
            throw URLError(.notConnectedToInternet)
        }
        do { try await client.revoke(); XCTFail("Expected offline error") } catch {}
        XCTAssertEqual(spy.urls, [server])
    }
    func testRetryAfterAndTransientErrorsPreserveStatus() async {
        for status in [400, 409, 413, 429, 503, 507] {
            StubProtocol.handler = { _ in (status, ["Retry-After": "12"], Data()) }
            do { _ = try await client.request("api/v1/me"); XCTFail("Expected error") }
            catch let error as APIError { XCTAssertEqual(error.status, status); XCTAssertEqual(error.retryAfter, 12) }
            catch { XCTFail("Unexpected error: \(error)") }
        }
    }
    func testTokenExchangeHasExactContractAndNoBearer() async throws {
        StubProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/api/v1/auth/token")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            let body = try XCTUnwrap(Self.body(request))
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: String])
            XCTAssertEqual(json, ["grant_type": "authorization_code", "code": String(repeating: "c", count: 43), "code_verifier": String(repeating: "v", count: 43), "redirect_uri": "http://127.0.0.1:18088/callback", "client_id": "agora-capture"])
            return (200, [:], Data("{\"access_token\":\"\(self.token)\",\"token_type\":\"Bearer\",\"token_id\":\"6f1c1f43-6a5e-4a3e-9d43-2a6f0f9d1c11\",\"email\":\"alex@example.com\"}".utf8))
        }
        let reply = try await AgoraClient.exchange(server: server, code: String(repeating: "c", count: 43), verifier: String(repeating: "v", count: 43), redirectURI: "http://127.0.0.1:18088/callback", configuration: config)
        XCTAssertEqual(reply.accessToken, token)
    }
    func testUploadUsesQueryAndParsesReturnedLink() async throws {
        StubProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/api/v1/captures")
            XCTAssertEqual(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems, [URLQueryItem(name: "duration", value: "6h")])
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertTrue(request.value(forHTTPHeaderField: "Content-Type")!.hasPrefix("multipart/form-data; boundary=Agora-"))
            return (200, [:], Data(#"{"url":"https://contract-test.invalid/s/Ab3dE6gH","token":"Ab3dE6gH","expiresAtUtc":"2099-11-05T09:30:00.123Z"}"#.utf8))
        }
        let reply = try await client.upload(Data([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), duration: "6h")
        XCTAssertEqual(reply.token, "Ab3dE6gH")
    }
    func testMultipartContainsNamedPNGFileAndClosingBoundary() throws {
        let png = Data([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
        let file = try AgoraClient.multipartFile(png, boundary: "test")
        defer { try? FileManager.default.removeItem(at: file) }
        let content = try Data(contentsOf: file)
        XCTAssertNotNil(content.range(of: Data("name=\"file\"; filename=\"capture.png\"\r\n".utf8)))
        XCTAssertNotNil(content.range(of: png))
        XCTAssertTrue(content.suffix(12).contains(Data("--test--".utf8)))
    }
    func testCallbackParsingIgnoresWrongStateAndRejectsDuplicates() throws {
        let code = String(repeating: "c", count: 43)
        XCTAssertEqual(try AuthCallback.parse("GET /callback?code=\(code)&state=correct HTTP/1.1\r\n\r\n", state: "correct"), .code(code))
        XCTAssertEqual(try AuthCallback.parse("GET /callback?error=access_denied&state=correct HTTP/1.1\r\n\r\n", state: "correct"), .denied)
        XCTAssertEqual(try AuthCallback.parse("GET /callback?error=invalid_request&state=correct HTTP/1.1\r\n\r\n", state: "correct"), .invalidRequest)
        for target in ["/callback?code=\(code)&state=wrong", "/callback?code=\(code)&code=\(code)&state=correct", "/callback?code=\(code)&state=correct&state=correct", "/other?code=\(code)&state=correct", "/callback?code=\(code)&error=access_denied&state=correct", "http://evil.test/callback?code=\(code)&state=correct"] {
            XCTAssertThrowsError(try AuthCallback.parse("GET \(target) HTTP/1.1\r\n\r\n", state: "correct"))
        }
    }
    func testServerOriginCanonicalization() throws {
        XCTAssertEqual(try AgoraClient.serverURL(" https://example.com/ ").absoluteString, "https://example.com")
        XCTAssertNoThrow(try AgoraClient.serverURL("http://[::1]:18080"))
        XCTAssertThrowsError(try AgoraClient.serverURL("https://example.com:99999"))
    }
    private static func body(_ request: URLRequest) -> Data? {
        if let data = request.httpBody { return data }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open(); defer { stream.close() }
        var data = Data(), bytes = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable { let n = stream.read(&bytes, maxLength: bytes.count); if n <= 0 { break }; data.append(contentsOf: bytes.prefix(n)) }
        return data
    }
}
private extension String { var prependingBearer: String { "Bearer \(self)" } }

extension APIContractTests {
    @MainActor func testRealLoopbackRoundTripChecksStateBeforeExchanging() async throws {
        guard ProcessInfo.processInfo.environment["AGORA_TEST_LOOPBACK"] == "1" else { throw XCTSkip("Set AGORA_TEST_LOOPBACK=1 to exercise a real loopback socket") }
        let opened = expectation(description: "Browser opened")
        var authorizationURL: URL?
        let auth = BrowserAuth(openBrowser: { url in authorizationURL = url; opened.fulfill(); return true }, configuration: config)
        StubProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/api/v1/auth/token")
            return (200, [:], Data("{\"access_token\":\"\(self.token)\",\"token_type\":\"Bearer\",\"token_id\":\"6f1c1f43-6a5e-4a3e-9d43-2a6f0f9d1c11\",\"email\":\"alex@example.com\"}".utf8))
        }
        let task = Task { try await auth.connect(server: server) }
        defer { auth.cancel(); task.cancel() }
        await fulfillment(of: [opened], timeout: 5)
        let url = try XCTUnwrap(authorizationURL)
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!
        let redirect = try XCTUnwrap(items.first(where: { $0.name == "redirect_uri" })?.value)
        let state = try XCTUnwrap(items.first(where: { $0.name == "state" })?.value)
        let code = String(repeating: "c", count: 43)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let (_, invalid) = try await session.data(from: URL(string: "\(redirect)?code=\(code)&state=wrong")!)
        XCTAssertEqual((invalid as? HTTPURLResponse)?.statusCode, 400)
        let (_, valid) = try await session.data(from: URL(string: "\(redirect)?code=\(code)&state=\(state)")!)
        XCTAssertEqual((valid as? HTTPURLResponse)?.statusCode, 200)
        let received = try await task.value
        XCTAssertEqual(received, token)
    }
}
