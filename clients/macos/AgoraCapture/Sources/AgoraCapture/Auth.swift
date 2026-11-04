import AppKit
import Network

// Separate callback parsing keeps untrusted loopback input out of the sign-in state machine.
enum AuthCallback: Equatable {
    case code(String)
    case denied
    case invalidRequest
    static func parse(_ request: String, state: String) throws -> AuthCallback {
        let first = request.components(separatedBy: "\r\n").first ?? ""
        let parts = first.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "GET", parts[2].hasPrefix("HTTP/1."),
              let url = URLComponents(string: String(parts[1])), url.scheme == nil, url.host == nil,
              url.path == "/callback", url.fragment == nil else { throw ClientError(message: "Invalid sign-in callback.") }
        let items = url.queryItems ?? []
        guard Set(items.map(\.name)).count == items.count, items.first(where: { $0.name == "state" })?.value == state else {
            throw ClientError(message: "Invalid sign-in state.")
        }
        let code = items.first(where: { $0.name == "code" })?.value
        let error = items.first(where: { $0.name == "error" })?.value
        if let error, code == nil {
            switch error {
            case "access_denied": return .denied
            case "invalid_request": return .invalidRequest
            default: throw ClientError(message: "Unknown sign-in callback error.")
            }
        }
        guard error == nil, let code, code.count == 43,
              code.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_").contains($0) }) else {
            throw ClientError(message: "Invalid authorization code.")
        }
        return .code(code)
    }
}

@MainActor final class BrowserAuth {
    private var listener: NWListener?
    private var continuation: CheckedContinuation<String, Error>?
    private var timeout: Task<Void, Never>?
    private var exchange: Task<Void, Never>?
    private var attempt: UUID?
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var exchanging = false
    private let openBrowser: @MainActor (URL) -> Bool
    private let configuration: URLSessionConfiguration
    init(openBrowser: @escaping @MainActor (URL) -> Bool = { NSWorkspace.shared.open($0) }, configuration: URLSessionConfiguration = .ephemeral) {
        self.openBrowser = openBrowser; self.configuration = configuration
    }
    func connect(server: URL) async throws -> String {
        guard continuation == nil else { throw ClientError(message: "A sign-in is already in progress.") }
        try Task.checkCancellation()
        let id = UUID(), verifier = try PKCE.random(32), state = try PKCE.random(16)
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener; attempt = id; exchanging = false
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                listener.stateUpdateHandler = { [weak self] status in
                    Task { @MainActor in
                        guard let self, self.attempt == id else { return }
                        switch status {
                        case .ready:
                            guard let port = listener.port, port.rawValue >= 1024 else {
                                self.finish(.failure(ClientError(message: "Could not open a sign-in callback port."))); return
                            }
                            let redirect = "http://127.0.0.1:\(port.rawValue)/callback"
                            var url = URLComponents(url: server.appendingPathComponent("connect/authorize"), resolvingAgainstBaseURL: false)!
                            url.queryItems = [URLQueryItem(name: "client_id", value: "agora-capture"), URLQueryItem(name: "redirect_uri", value: redirect), URLQueryItem(name: "state", value: state), URLQueryItem(name: "code_challenge", value: PKCE.challenge(verifier)), URLQueryItem(name: "code_challenge_method", value: "S256"), URLQueryItem(name: "device_name", value: "AgoraCapture on \(Host.current().localizedName ?? "Mac")")]
                            if !self.openBrowser(url.url!) { self.finish(.failure(ClientError(message: "Could not open the sign-in browser."))) }
                        case .failed(let error): self.finish(.failure(error))
                        default: break
                        }
                    }
                }
                listener.newConnectionHandler = { [weak self] connection in
                    Task { @MainActor in
                        guard let self, self.attempt == id, !self.exchanging, let port = listener.port else { connection.cancel(); return }
                        let redirect = "http://127.0.0.1:\(port.rawValue)/callback"
                        self.connections[ObjectIdentifier(connection)] = connection
                        connection.start(queue: .main)
                        self.readHeaders(connection, attempt: id) { [weak self] request in
                            self?.handle(request, connection: connection, server: server, redirect: redirect, verifier: verifier, state: state, attempt: id)
                        }
                    }
                }
                listener.start(queue: .main)
                timeout = Task { [weak self] in
                    do { try await Task.sleep(for: .seconds(300)) } catch { return }
                    guard self?.attempt == id else { return }
                    self?.finish(.failure(ClientError(message: "Sign-in timed out. Try connecting again.")))
                }
            }
        }, onCancel: { Task { @MainActor in if self.attempt == id { self.cancel() } } })
    }
    private func handle(_ request: String, connection: NWConnection, server: URL, redirect: String, verifier: String, state: String, attempt id: UUID) {
        guard attempt == id, !exchanging else { reply(connection, status: "400 Bad Request", message: "Sign-in already handled."); return }
        let callback: AuthCallback
        do { callback = try AuthCallback.parse(request, state: state) }
        catch { reply(connection, status: "400 Bad Request", message: "Invalid sign-in callback. Please return to Agora Capture."); return }
        // Remove the connection before finishing so its response can drain normally.
        let outcome: CallbackPage.Outcome
        switch callback {
        case .code: outcome = .approved
        case .denied: outcome = .declined
        case .invalidRequest: outcome = .invalid
        }
        reply(connection, status: "200 OK", outcome: outcome)
        listener?.cancel(); listener = nil
        switch callback {
        case .denied: finish(.failure(ClientError(message: "You declined the connection. No app token was issued.")))
        case .invalidRequest: finish(.failure(ClientError(message: "Agora rejected the sign-in parameters. Check server compatibility and try again.")))
        case .code(let code):
            exchanging = true
            exchange = Task { [weak self] in
                do {
                    let result = try await AgoraClient.exchange(server: server, code: code, verifier: verifier, redirectURI: redirect, configuration: self?.configuration ?? .ephemeral)
                    try Task.checkCancellation()
                    guard self?.attempt == id else { return }
                    self?.finish(.success(result.accessToken))
                } catch {
                    guard self?.attempt == id else { return }
                    self?.finish(.failure(error))
                }
            }
        }
    }
    func cancel() { finish(.failure(CancellationError())) }
    private func finish(_ result: Result<String, Error>) {
        attempt = nil
        timeout?.cancel(); timeout = nil; exchange?.cancel(); exchange = nil
        listener?.cancel(); listener = nil
        connections.values.forEach { $0.cancel() }; connections.removeAll()
        let completion = continuation; continuation = nil; completion?.resume(with: result)
    }
    private func readHeaders(_ connection: NWConnection, attempt id: UUID, accumulated: Data = Data(), completion: @escaping @MainActor (String) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, ended, error in
            Task { @MainActor in
                guard let self, self.attempt == id else { connection.cancel(); return }
                var buffer = accumulated
                if let data { buffer.append(data) }
                guard buffer.count <= 16384, error == nil else { self.drop(connection); return }
                if let request = String(data: buffer, encoding: .utf8), request.contains("\r\n\r\n") { completion(request) }
                else if ended { self.drop(connection) }
                else { self.readHeaders(connection, attempt: id, accumulated: buffer, completion: completion) }
            }
        }
    }
    private func drop(_ connection: NWConnection) { connections.removeValue(forKey: ObjectIdentifier(connection)); connection.cancel() }
    private func reply(_ connection: NWConnection, status: String, message: String? = nil, outcome: CallbackPage.Outcome = .invalid) {
        connections.removeValue(forKey: ObjectIdentifier(connection))
        let body = CallbackPage.html(outcome: outcome, message: message)
        let response = "HTTP/1.1 \(status)\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\n\(CallbackPage.securityHeaders)Connection: close\r\n\r\n\(body)"
        connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
    }
}
