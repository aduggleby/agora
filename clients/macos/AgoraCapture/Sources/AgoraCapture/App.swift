import AppKit
import SwiftUI
import Carbon
import ServiceManagement

@main struct AgoraCaptureMain {
    static func main() {
        let app = NSApplication.shared
        let delegate = CaptureApp()
        if let index = CommandLine.arguments.firstIndex(of: "--render-previews"), CommandLine.arguments.count > index + 1 {
            do { try renderPreviews(app: delegate, directory: CommandLine.arguments[index + 1]) } catch { fputs("Preview rendering failed: \(error)\n", stderr) }
            return
        }
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
        withExtendedLifetime(delegate) {}
    }
}
@MainActor final class CaptureApp: NSObject, NSApplicationDelegate, ObservableObject, NSMenuDelegate, NSWindowDelegate {
    @Published var serverText = UserDefaults.standard.string(forKey: "server") ?? ""
    @Published var connectedServer: URL?
    @Published var refreshing = false
    @Published var disconnecting = false
    @Published var account: Account?
    @Published var message: String?
    @Published var connecting = false
    @Published var recent: [RecentLink] = []
    @Published var capturing = false
    @Published var shortcutPreset = UserDefaults.standard.integer(forKey: "shortcutPreset")
    var durations: [String] { account?.directLinkDurations ?? [] }
    var statusItem: NSStatusItem!
    var settingsWindow: NSWindow?
    var editorWindows: [NSWindow] = []
    var toast: NSPanel?
    var toastTimer: Timer?
    var toastRemaining = 15
    var toastHovered = false
    let auth = BrowserAuth()
    var hotKeys: [EventHotKeyRef] = []
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let icon = Bundle.main.url(forResource: "AgoraCapture", withExtension: "icns").flatMap(NSImage.init(contentsOf:)) {
            NSApp.applicationIconImage = icon
        }
        UserDefaults.standard.removeObject(forKey: "demo")
        if let data = UserDefaults.standard.data(forKey: "recent"), let links = try? JSONDecoder().decode([RecentLink].self, from: data) {
            recent = links.filter { $0.url.host != "demo.invalid" }; persistRecent()
        }
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.image = CaptureBrand.menuIcon
        let menu = NSMenu(); menu.delegate = self; statusItem.menu = menu
        registerHotkeys()
        Task { await refreshAccount() }
        if UserDefaults.standard.object(forKey: "hasLaunched") == nil || !hasStoredCredentials { showSettings(); UserDefaults.standard.set(true, forKey: "hasLaunched") }
    }
    func menuWillOpen(_ menu: NSMenu) {
        menu.removeAllItems()
        func item(_ title: String, _ action: Selector, enabled: Bool = true) { let i = NSMenuItem(title: title, action: action, keyEquivalent: ""); i.target = self; i.isEnabled = enabled; menu.addItem(i) }
        item("Capture area", #selector(area), enabled: !capturing)
        item("Capture full screen", #selector(fullScreen), enabled: !capturing)
        menu.addItem(.separator())
        let heading = NSMenuItem(title: "Recent links", action: nil, keyEquivalent: ""); menu.addItem(heading)
        if recent.isEmpty { menu.addItem(NSMenuItem(title: "No links yet", action: nil, keyEquivalent: "")) }
        for link in recent {
            let label = (link.expiresAt < Date() ? "Expired · " : "") + link.createdAt.formatted(date: .abbreviated, time: .shortened)
            let parent = NSMenuItem(title: label, action: nil, keyEquivalent: "")
            let sub = NSMenu()
            for (title, action) in [("Copy link", #selector(copyRecent(_:))), ("Open in browser", #selector(openRecent(_:))), ("Delete link…", #selector(deleteRecent(_:)))] {
                let i = NSMenuItem(title: title, action: action, keyEquivalent: ""); i.target = self; i.representedObject = link; sub.addItem(i)
            }
            parent.submenu = sub; menu.addItem(parent)
        }
        menu.addItem(.separator()); item("Settings…", #selector(showSettings)); item("Quit Agora Capture", #selector(quit))
    }
    @objc func quit() { NSApp.terminate(nil) }
    @objc func area() { capture(area: true) }
    @objc func fullScreen() { capture(area: false) }
    func capture(area: Bool) {
        guard !capturing else { return }
        guard CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess() else {
            let alert = NSAlert(); alert.messageText = "Allow Screen Recording"; alert.informativeText = "Agora Capture needs Screen Recording permission to capture your screen. Enable it in System Settings, then reopen the app if requested."; alert.addButton(withTitle: "Open Settings"); alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture")!) }; return
        }
        capturing = true
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("agora-\(UUID().uuidString).png")
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        var args = ["-x"]
        if area { args.append("-i") } else {
            let mouse = NSEvent.mouseLocation
            let screen = NSScreen.screens.firstIndex(where: { $0.frame.contains(mouse) }) ?? 0
            args += ["-D", "\(screen + 1)"]
        }
        process.arguments = args + [file.path]
        process.terminationHandler = { [weak self] _ in Task { @MainActor in
            defer { try? FileManager.default.removeItem(at: file); self?.capturing = false }
            if let image = NSImage(contentsOf: file) { self?.openEditor(image) }
        } }
        do { try process.run() } catch { capturing = false; message = error.localizedDescription; showSettings() }
    }
    func openEditor(_ image: NSImage) {
        let model = EditorModel(image: image)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 760), styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.title = "Agora Capture"; window.isReleasedWhenClosed = false; window.delegate = self
        window.contentView = NSHostingView(rootView: EditorView(model: model, app: self, close: { [weak window] in window?.close() }))
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
        editorWindows.removeAll { !$0.isVisible }; editorWindows.append(window)
    }
    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        window.contentView = nil
        editorWindows.removeAll { $0 === window }
    }
    @objc func showSettings() {
        if settingsWindow == nil || settingsWindow?.contentView == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 540, height: 590), styleMask: [.titled, .closable], backing: .buffered, defer: false)
            w.title = "Agora Capture Settings"; w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: SettingsView(app: self)); w.center(); settingsWindow = w
        }
        settingsWindow?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    var hasStoredCredentials: Bool {
        guard let server = try? AgoraClient.serverURL(serverText) else { return false }
        return Keychain.read(server: server) != nil
    }
    func client() throws -> AgoraClient {
        let url = try AgoraClient.serverURL(serverText)
        guard let token = Keychain.read(server: url) else { throw ClientError(message: "Connect to Agora in Settings first.") }
        return AgoraClient(server: url, token: token)
    }
    func handleAPIError(_ error: Error, server: URL) {
        if let api = error as? APIError, api.requiresReconnect,
           (try? AgoraClient.serverURL(serverText)) == server {
            account = nil; connectedServer = nil
            message = api.localizedDescription
        }
    }
    func refreshAccount() async {
        guard !refreshing else { return }
        guard hasStoredCredentials else { account = nil; connectedServer = nil; return }
        refreshing = true
        defer { refreshing = false }
        do {
            let c = try client(); connectedServer = c.server
            account = try await c.me(); message = nil
        } catch {
            if let server = try? AgoraClient.serverURL(serverText) { handleAPIError(error, server: server) }
            message = error.localizedDescription
        }
    }
    func connect() async {
        guard !connecting, !disconnecting else { return }
        connecting = true; message = nil
        defer { connecting = false }
        do {
            let server = try AgoraClient.serverURL(serverText)
            serverText = server.absoluteString; UserDefaults.standard.set(serverText, forKey: "server")
            let token = try await auth.connect(server: server)
            try Keychain.save(token, server: server)
            connectedServer = server
            account = try await AgoraClient(server: server, token: token).me()
            message = "Connected. You're ready to capture."
        } catch {
            if let server = try? AgoraClient.serverURL(serverText) { handleAPIError(error, server: server) }
            message = error is CancellationError ? "Sign-in cancelled." : error.localizedDescription
        }
    }
    func disconnect() async {
        guard !disconnecting else { return }
        disconnecting = true
        defer { disconnecting = false; account = nil; connectedServer = nil }
        do { try await client().revoke(); message = "Disconnected." }
        catch {
            if let server = try? AgoraClient.serverURL(serverText) { Keychain.remove(server: server) }
            if let api = error as? APIError, api.requiresReconnect { message = "Disconnected." }
            else { message = "Disconnected locally. The server could not confirm revocation. You can revoke this device under Connected apps in Agora." }
        }
    }
    func upload(_ png: Data, duration: String, progress: @escaping @Sendable (Double) -> Void) async throws -> RecentLink {
        let c = try client()
        do {
            let info = try await c.me(); account = info
            guard info.directLinkDurations.contains(duration) else { throw ClientError(message: "Choose a duration supported by this server.") }
            guard png.count <= info.maxFileSizeBytes else { throw ClientError(message: "This capture exceeds the server's file size limit.") }
            let result = try await c.upload(png, duration: duration, progress: progress)
            let link = RecentLink(url: result.url, token: result.token, expiresAt: result.expiresAtUtc, createdAt: Date(), server: c.server)
            recent.insert(link, at: 0); recent = Array(recent.prefix(10)); persistRecent(); copy(link.url)
            return link
        } catch { handleAPIError(error, server: c.server); throw error }
    }
    func persistRecent() { if let data = try? JSONEncoder().encode(recent) { UserDefaults.standard.set(data, forKey: "recent") } }
    func copy(_ url: URL) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(url.absoluteString, forType: .string) }
    @objc func copyRecent(_ sender: NSMenuItem) { if let link = sender.representedObject as? RecentLink { copy(link.url) } }
    @objc func openRecent(_ sender: NSMenuItem) { if let link = sender.representedObject as? RecentLink { NSWorkspace.shared.open(link.url) } }
    @objc func deleteRecent(_ sender: NSMenuItem) {
        guard let link = sender.representedObject as? RecentLink else { return }
        let alert = NSAlert(); alert.messageText = "Delete this link?"; alert.informativeText = "Anyone with this link will lose access."; alert.addButton(withTitle: "Delete link"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Task {
            do {
                guard let token = Keychain.read(server: link.server) else { throw ClientError(message: "Reconnect to this link's server before deleting it.") }
                do { try await AgoraClient(server: link.server, token: token).deleteShare(link.token) }
                catch { handleAPIError(error, server: link.server); throw error }
                recent.removeAll { $0.id == link.id }; persistRecent()
            } catch { message = error.localizedDescription; showSettings() }
        }
    }
    func showToast(_ link: RecentLink, image: NSImage) {
        toastTimer?.invalidate(); toast?.close(); toastRemaining = 15; toastHovered = false
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 420, height: 160), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.level = .floating; panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]; panel.isReleasedWhenClosed = false; panel.hasShadow = true
        panel.contentView = NSHostingView(rootView: ToastView(link: link, image: image, copy: { self.copy(link.url) }, close: { self.dismissToast() }, hover: { self.toastHovered = $0 }))
        let screen = NSScreen.screens.first(where: { $0.frame.contains(NSEvent.mouseLocation) }) ?? NSScreen.main!
        panel.setFrameOrigin(NSPoint(x: screen.visibleFrame.maxX - 440, y: screen.visibleFrame.maxY - 180)); panel.orderFrontRegardless(); toast = panel
        toastTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in Task { @MainActor in guard let self, !self.toastHovered else { return }; self.toastRemaining -= 1; if self.toastRemaining <= 0 { self.dismissToast() } } }
    }
    func dismissToast() { toastTimer?.invalidate(); toastTimer = nil; toast?.close(); toast = nil }
    func registerHotkeys() {
        hotKeys.forEach { UnregisterEventHotKey($0) }; hotKeys.removeAll()
        struct Handler { static var installed = false }
        if !Handler.installed {
            var event = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
            InstallEventHandler(GetApplicationEventTarget(), { _, event, context in
                guard let event, let context else { return noErr }
                var id = EventHotKeyID(); GetEventParameter(event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID), nil, MemoryLayout<EventHotKeyID>.size, nil, &id)
                let app = Unmanaged<CaptureApp>.fromOpaque(context).takeUnretainedValue()
                Task { @MainActor in app.capture(area: id.id == 1) }; return noErr
            }, 1, &event, Unmanaged.passUnretained(self).toOpaque(), nil)
            Handler.installed = true
        }
        let modifiers = UInt32(controlKey | shiftKey | (shortcutPreset == 1 ? optionKey : 0))
        for (index, code) in [UInt32(kVK_ANSI_A), UInt32(kVK_ANSI_S)].enumerated() {
            var ref: EventHotKeyRef?
            let result = RegisterEventHotKey(code, modifiers, EventHotKeyID(signature: 0x41474F52, id: UInt32(index + 1)), GetApplicationEventTarget(), 0, &ref)
            if result == noErr, let ref { hotKeys.append(ref) } else { message = "A capture shortcut is already in use. Choose the alternate shortcuts in Settings." }
        }
        UserDefaults.standard.set(shortcutPreset, forKey: "shortcutPreset")
    }
}
struct SettingsView: View {
    @ObservedObject var app: CaptureApp
    @AppStorage("duration") var defaultDuration = "1d"
    @State var loginEnabled = SMAppService.mainApp.status == .enabled
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack { Image(nsImage: CaptureBrand.menuIcon).renderingMode(.template).resizable().frame(width: 32, height: 32).foregroundStyle(skyBlue); VStack(alignment: .leading) { Text("A detail worth sharing.").font(.system(size: 25, design: .serif)); Text("Agora Capture").foregroundStyle(.secondary) } }
            Text("Connect to your Agora server to create temporary image links.").font(.callout).foregroundStyle(.secondary)
            GroupBox("Your Agora server") {
                VStack(alignment: .leading, spacing: 12) {
                    TextField("https://files.example.com", text: $app.serverText).textFieldStyle(.roundedBorder).disabled(app.connecting || app.connectedServer != nil || app.refreshing || app.disconnecting).help("Disconnect before changing servers")
                    if let account = app.account { Label("Connected as \(account.email)", systemImage: "checkmark.circle.fill").foregroundStyle(.green) }
                    HStack {
                        if app.connecting { ProgressView().controlSize(.small); Button("Cancel sign-in") { app.auth.cancel() } }
                        else if app.connectedServer != nil {
                            Button(app.disconnecting ? "Disconnecting…" : "Disconnect") { Task { await app.disconnect() } }.disabled(app.disconnecting).help("Revoke this device and remove its saved token")
                            Button(app.refreshing ? "Checking…" : "Check connection") { Task { await app.refreshAccount() } }.disabled(app.refreshing || app.disconnecting).help("Reload account and capture limits")
                        } else { Button("Connect in browser") { Task { await app.connect() } }.help("Sign in securely in your browser") }
                    }
                }.padding(10)
            }
            GroupBox("Capture shortcuts") {
                Picker("Keys", selection: $app.shortcutPreset) { Text("⌃⇧A / ⌃⇧S").tag(0); Text("⌃⌥⇧A / ⌃⌥⇧S").tag(1) }.padding(10).onChange(of: app.shortcutPreset) { _, _ in app.registerHotkeys() }
            }
            Picker("Default duration", selection: $defaultDuration) {
                if app.durations.isEmpty { Text("Connect to load durations").tag(defaultDuration) }
                else { ForEach(app.durations, id: \.self) { Text(durationLabel($0)).tag($0) } }
            }.onChange(of: app.durations) { _, durations in
                if !durations.contains(defaultDuration), let first = durations.first { defaultDuration = first }
            }.disabled(app.durations.isEmpty).help(app.durations.isEmpty ? "Connect to load supported durations." : "Remembered for new captures")
            Toggle("Launch at login", isOn: $loginEnabled).onChange(of: loginEnabled) { _, enabled in
                do { if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } } catch { app.message = "Launch at login requires an installed, signed app. \(error.localizedDescription)"; loginEnabled = SMAppService.mainApp.status == .enabled }
            }
            if let message = app.message { Text(message).font(.callout).foregroundStyle(.secondary).textSelection(.enabled) }
            Spacer(minLength: 0)
            Text("Images stay local until you upload.").font(.caption).foregroundStyle(.secondary)
        }.padding(26).frame(width: 540, height: 590).tint(skyBlue)
    }
}
struct ToastView: View {
    let link: RecentLink
    let image: NSImage
    let copy: () -> Void
    let close: () -> Void
    let hover: (Bool) -> Void
    @State var copied = true
    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(nsImage: image).resizable().scaledToFit().frame(width: 76, height: 90).background(.white).clipShape(RoundedRectangle(cornerRadius: 6))
            VStack(alignment: .leading, spacing: 9) {
                Text("Link copied. Ready to share.").font(.headline)
                Text(link.url.absoluteString).font(.caption).lineLimit(1).truncationMode(.middle)
                Text("Expires \(link.expiresAt.formatted(.relative(presentation: .named)))").font(.caption).foregroundStyle(.secondary)
                Button(copied ? "Copied ✓" : "Copy link") { copy(); copied = true }.onAppear { DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false } }
            }
            Spacer(minLength: 0)
            Button(action: close) { Image(systemName: "xmark") }.buttonStyle(.plain).help("Dismiss")
        }.padding(18).frame(width: 420, height: 160).background(.regularMaterial).onHover(perform: hover).tint(skyBlue)
    }
}
