import AppKit
import ServiceManagement
import SwiftUI

struct SettingsView: View {
    @ObservedObject var app: CaptureApp
    @AppStorage("duration") var defaultDuration = "1d"
    @State private var loginEnabled = SMAppService.mainApp.status == .enabled
    private var serverLabel: String {
        guard let url = try? AgoraClient.serverURL(app.serverText), let host = url.host else { return app.serverText }
        return host + (url.port.map { ":\($0)" } ?? "")
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 13) {
                    Image(nsImage: CaptureBrand.menuIcon).renderingMode(.template).resizable().frame(width: 28, height: 28).foregroundStyle(skyBlue)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Settings").font(.system(size: 25, weight: .semibold))
                        Text("Agora Capture").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }.padding(.bottom, 30)
                heading("Connection").padding(.bottom, 12)
                connectionCard
                if let message = app.message {
                    Text(message).font(.system(size: 12)).foregroundStyle(.secondary).textSelection(.enabled).fixedSize(horizontal: false, vertical: true).padding(.top, 10)
                }
                heading("Shortcuts").padding(.top, 28).padding(.bottom, 12)
                ForEach(CaptureAction.allCases, id: \.self) { action in
                    HStack {
                        Text(action.title).font(.system(size: 14))
                        Spacer()
                        ShortcutRecorder(app: app, action: action)
                    }.padding(.bottom, action == .area ? 12 : 0)
                }
                Text(app.shortcutError ?? (app.recordingAction == nil ? "Click a shortcut to record a new key combination." : "Press your new shortcut. Escape cancels."))
                    .font(.system(size: 11)).foregroundStyle(app.shortcutError == nil ? Color.secondary : .red)
                    .fixedSize(horizontal: false, vertical: true).padding(.top, 12)
                Divider().padding(.vertical, 25)
                HStack {
                    Text("Keep links for").font(.system(size: 14))
                    Spacer()
                    Picker("Keep links for", selection: $defaultDuration) {
                        if app.durations.isEmpty { Text("Connect first").tag(defaultDuration) }
                        else { ForEach(app.durations, id: \.self) { Text(durationLabel($0)).tag($0) } }
                    }.labelsHidden().frame(width: 126).disabled(app.durations.isEmpty)
                        .help(app.durations.isEmpty ? "Connect to Agora to load expiry choices" : "Default expiry for new captures; you can change it before sharing")
                }
                Text("Default expiry for new links.\nYou can change it for each capture before sharing.")
                    .font(.system(size: 12)).foregroundStyle(.secondary).lineSpacing(4).padding(.top, 10)
                Divider().padding(.vertical, 25)
                HStack {
                    Text("Launch at login").font(.system(size: 14))
                    Spacer()
                    Toggle("Launch at login", isOn: $loginEnabled).labelsHidden().toggleStyle(.switch).controlSize(.small)
                }
                    .onChange(of: loginEnabled) { _, enabled in
                        do {
                            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
                        } catch {
                            app.message = "Launch at login requires an installed, signed app. \(error.localizedDescription)"
                            let actual = SMAppService.mainApp.status == .enabled
                            if loginEnabled != actual { loginEnabled = actual }
                        }
                    }
                Text("Images stay on your Mac until you share them.").font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, 36)
            }.padding(.horizontal, 34).padding(.top, 28).padding(.bottom, 28)
        }.frame(width: 540, height: 720).background(Color(nsColor: .windowBackgroundColor)).tint(skyBlue)
            .onChange(of: app.durations) { _, durations in
                if !durations.contains(defaultDuration), let first = durations.first { defaultDuration = first }
            }.onDisappear { app.endShortcutRecording() }
    }
    private func heading(_ text: String) -> some View {
        Text(text.uppercased()).font(.system(size: 11, weight: .semibold)).tracking(1.3).foregroundStyle(.secondary)
    }
    private var connectionCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            if app.connectedServer != nil {
                HStack {
                    Text(serverLabel).font(.system(size: 15, weight: .medium)).textSelection(.enabled)
                    Spacer()
                    Image(systemName: "lock").font(.system(size: 12)).foregroundStyle(.secondary)
                }
            } else {
                TextField("https://files.example.com", text: $app.serverText).textFieldStyle(.roundedBorder)
                    .disabled(app.connecting || app.refreshing).help(app.connecting ? "Finish or cancel sign-in before changing servers" : "Your Agora server address")
                    .onSubmit { Task { await app.connect() } }
            }
            HStack(spacing: 7) {
                if app.connecting {
                    ProgressView().controlSize(.small)
                    Text("Waiting for browser approval…").font(.system(size: 12)).foregroundStyle(.secondary)
                    Spacer(minLength: 0)
                    Button("Cancel") { app.auth.cancel() }.buttonStyle(.plain).foregroundStyle(skyBlue)
                } else if app.connectedServer != nil {
                    Circle().fill(app.account == nil ? Color.orange : .green).frame(width: 6, height: 6)
                    Text(verbatim: app.account?.email ?? "Connection unavailable").font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 8)
                    Button { Task { await app.refreshAccount() } } label: { Image(systemName: "arrow.clockwise").font(.system(size: 12)) }
                        .buttonStyle(.plain).foregroundStyle(.secondary).disabled(app.refreshing || app.disconnecting)
                        .help(app.refreshing ? "Checking connection" : "Check connection and refresh server limits").accessibilityLabel("Check connection")
                    Button(app.disconnecting ? "Disconnecting…" : "Disconnect") { Task { await app.disconnect() } }
                        .font(.system(size: 12, weight: .medium)).buttonStyle(.plain).foregroundStyle(skyBlue)
                        .disabled(app.disconnecting || app.refreshing).help("Revoke this device and remove its saved credentials")
                } else {
                    Button("Connect in browser") { Task { await app.connect() } }.buttonStyle(CaptureActionStyle(primary: true))
                    Spacer()
                }
            }
        }.padding(18).background(Color.primary.opacity(0.025), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.07), lineWidth: 1))
    }
}
