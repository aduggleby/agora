import Foundation

/// Static, self-contained HTML: the browser never sends callback codes to font/CDN services.
enum CallbackPage {
    enum Outcome { case approved, declined, invalid }
    static let securityHeaders = "Cache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n"

    static func html(outcome: Outcome, message: String? = nil, fontDirectory: URL? = Bundle.main.resourceURL?.appendingPathComponent("Fonts")) -> String {
        let title: String, status: String, explanation: String, symbol: String
        switch outcome {
        case .approved:
            title = "Back to capturing."
            status = "Approval received"
            explanation = "Return to Agora Capture to finish connecting your account."
            symbol = "<path d=\"m6 12 4 4 8-8\"/>"
        case .declined:
            title = "Connection declined."
            status = "No access granted"
            explanation = "You chose not to connect this device. You can try again from the app whenever you're ready."
            symbol = "<path d=\"m8 8 8 8m0-8-8 8\"/>"
        case .invalid:
            title = "Let's try that again."
            status = "Connection not completed"
            explanation = message ?? "Return to the app and choose Connect in browser to start again."
            symbol = "<path d=\"M12 7v6m0 4h.01\"/><circle cx=\"12\" cy=\"12\" r=\"9\"/>"
        }
        let focus = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M15 35V15h20m30 0h20v20m0 30v20H65m-30 0H15V65\"/><circle cx=\"50\" cy=\"50\" r=\"10\" fill=\"currentColor\" stroke=\"none\"/></svg>"
        let fonts = [("DM Sans", "DMSans-Regular.ttf", 400), ("DM Sans", "DMSans-Medium.ttf", 500), ("DM Sans", "DMSans-Semibold.ttf", 600), ("Instrument Serif", "InstrumentSerif-Regular.ttf", 400)].compactMap { family, file, weight -> String? in
            guard let fontDirectory else { return nil }
            // Xcode may flatten resource groups; command-line bundles retain Fonts/.
            let candidates = [fontDirectory.appendingPathComponent(file), fontDirectory.deletingLastPathComponent().appendingPathComponent(file)]
            guard let data = candidates.lazy.compactMap({ try? Data(contentsOf: $0) }).first else { return nil }
            return "@font-face{font-family:'\(family)';font-style:normal;font-weight:\(weight);font-display:swap;src:url(data:font/ttf;base64,\(data.base64EncodedString())) format('truetype')}"
        }.joined(separator: "\n")
        let favicon = focus.replacingOccurrences(of: "currentColor", with: "#0EA5E9")
        let isError = outcome == .invalid
        return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <meta name="referrer" content="no-referrer">
          <title>\(escape(status)) - Agora Capture</title>
          <link rel="icon" href="data:image/svg+xml;base64,\(Data(favicon.utf8).base64EncodedString())">
          <style>
          \(fonts)
          :root{color-scheme:light;--cream:#FAF7F2;--ink:#1A1614;--muted:#5C534A;--border:#E5DFD7;--terra:#C4663A}
          *{box-sizing:border-box}body{margin:0;background:var(--cream);color:var(--ink);font:14px/1.65 'DM Sans',sans-serif;min-height:100vh}
          .brand{display:flex;align-items:center;justify-content:center;gap:10px;padding:40px 24px 0;font:28px/1 'Instrument Serif',serif;text-decoration:none;color:var(--ink)}
          .brand-icon{display:grid;place-items:center;background:var(--terra);color:white;width:30px;height:30px;border-radius:8px}.brand-icon svg{width:19px;height:19px}
          main{width:min(100% - 40px,448px);margin:76px auto 48px}h1{font:400 36px/1.15 'Instrument Serif',serif;letter-spacing:-.6px;text-align:center;margin:0 0 30px}
          .card{background:white;border:1px solid var(--border);border-radius:18px;padding:28px}
          .status{display:flex;align-items:center;gap:9px;font-weight:500;color:\(isError ? "#B91C1C" : "#5B7A5E")}.status svg{width:21px;height:21px;flex-shrink:0}
          .description{color:var(--muted);margin:14px 0 24px}.app{display:flex;align-items:center;gap:12px;background:var(--cream);border:1px solid var(--border);border-radius:12px;padding:15px 16px;margin-bottom:24px}
          .app-icon{display:grid;place-items:center;width:38px;height:38px;flex-shrink:0;background:#0EA5E9;color:white;border-radius:10px}.app-icon svg{width:27px;height:27px}
          .app-name{font-weight:500}.app-meta{color:var(--muted);font-size:12px}
          .button{display:block;width:100%;padding:11px 16px;border-radius:9px;background:var(--terra);color:white;text-align:center;text-decoration:none;font-weight:500;transition:background .15s}
          .button:hover{background:#A8512B}.button:focus-visible{outline:3px solid #E8A17D;outline-offset:4px}
          .hint{margin:14px 0 0;color:#746A61;font-size:12px;text-align:center}.footer{color:#746A61;font-size:12px;text-align:center;margin:20px 0 0}
          @media(max-width:480px){.brand{padding-top:28px}main{margin-top:48px}.card{padding:24px}h1{font-size:32px}}
          </style>
        </head>
        <body>
          <div class="brand" aria-label="Agora">
            <span class="brand-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m10 13 4-4m-5 7-2 2a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 0 2-2a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0"/></svg></span>
            Agora
          </div>
          <main>
            <h1>\(escape(title))</h1>
            <section class="card" aria-label="Connection status">
              <div class="status" role="status"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">\(symbol)</svg>\(escape(status))</div>
              <p class="description">\(escape(explanation))</p>
              <div class="app"><span class="app-icon" aria-hidden="true">\(focus)</span><div><div class="app-name">Agora Capture</div><div class="app-meta">Your macOS capture app</div></div></div>
              <a class="button" href="agora-capture://auth/complete">Return to Agora Capture</a>
              <p class="hint">\(outcome == .approved ? "Check the app for your connection status." : "Start a new connection from Settings in the app.")</p>
            </section>
            <p class="footer">You can close this tab.</p>
          </main>
        </body>
        </html>
        """
    }
    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;").replacingOccurrences(of: "'", with: "&#39;")
    }
}
