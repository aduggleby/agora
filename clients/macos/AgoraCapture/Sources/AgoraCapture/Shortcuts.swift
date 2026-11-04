import AppKit
import Carbon
import SwiftUI

enum CaptureAction: UInt32, CaseIterable {
    case area = 1, fullScreen = 2
    var preferenceKey: String { self == .area ? "areaShortcut" : "screenShortcut" }
    var title: String { self == .area ? "Capture area" : "Capture full screen" }
}
struct CaptureShortcut: Codable, Equatable {
    let keyCode: UInt32
    let modifiers: UInt32
    let keyLabel: String
    var display: String {
        var parts: [String] = []
        if modifiers & UInt32(controlKey) != 0 { parts.append("⌃") }
        if modifiers & UInt32(optionKey) != 0 { parts.append("⌥") }
        if modifiers & UInt32(shiftKey) != 0 { parts.append("⇧") }
        if modifiers & UInt32(cmdKey) != 0 { parts.append("⌘") }
        return (parts + [keyLabel]).joined(separator: " ")
    }
    var isValid: Bool {
        let allowed = UInt32(controlKey | optionKey | shiftKey | cmdKey)
        return keyCode < 128 && !keyLabel.isEmpty && keyLabel.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) && modifiers & ~allowed == 0 && modifiers & UInt32(controlKey | optionKey | cmdKey) != 0
    }
    func matches(_ other: CaptureShortcut) -> Bool { keyCode == other.keyCode && modifiers == other.modifiers }
    static func load(_ action: CaptureAction, defaults: UserDefaults = .standard) -> CaptureShortcut {
        if let data = defaults.data(forKey: action.preferenceKey), let saved = try? JSONDecoder().decode(Self.self, from: data), saved.isValid { return saved }
        // Preserve the earlier alternate preset when upgrading to independent recorders.
        return CaptureShortcut(keyCode: UInt32(action == .area ? kVK_ANSI_A : kVK_ANSI_S), modifiers: UInt32(controlKey | shiftKey | (defaults.integer(forKey: "shortcutPreset") == 1 ? optionKey : 0)), keyLabel: action == .area ? "A" : "S")
    }
    init(keyCode: UInt32, modifiers: UInt32, keyLabel: String) { self.keyCode = keyCode; self.modifiers = modifiers; self.keyLabel = keyLabel }
    init(event: NSEvent) {
        keyCode = UInt32(event.keyCode)
        var flags: UInt32 = 0
        if event.modifierFlags.contains(.control) { flags |= UInt32(controlKey) }
        if event.modifierFlags.contains(.option) { flags |= UInt32(optionKey) }
        if event.modifierFlags.contains(.shift) { flags |= UInt32(shiftKey) }
        if event.modifierFlags.contains(.command) { flags |= UInt32(cmdKey) }
        modifiers = flags
        let special: [UInt16: String] = [36: "↩", 48: "⇥", 49: "Space", 51: "⌫", 76: "⌤", 117: "⌦", 123: "←", 124: "→", 125: "↓", 126: "↑", 115: "Home", 119: "End", 116: "PgUp", 121: "PgDn", 122: "F1", 120: "F2", 99: "F3", 118: "F4", 96: "F5", 97: "F6", 98: "F7", 100: "F8", 101: "F9", 109: "F10", 103: "F11", 111: "F12", 105: "F13", 107: "F14", 113: "F15", 106: "F16", 64: "F17", 79: "F18", 80: "F19", 90: "F20"]
        keyLabel = special[event.keyCode] ?? (event.charactersIgnoringModifiers ?? "").uppercased()
    }
}

struct ShortcutRecorder: View {
    @ObservedObject var app: CaptureApp
    let action: CaptureAction
    var body: some View {
        let recording = app.recordingAction == action
        Button { app.beginShortcutRecording(action) } label: {
            HStack(spacing: 12) {
                Text(recording ? "Press keys…" : app.shortcut(for: action).display).font(.system(size: 14, weight: .medium)).lineLimit(1)
                Image(systemName: "keyboard").font(.system(size: 12)).foregroundStyle(.secondary)
            }.frame(width: 126, height: 38)
                .background(recording ? skyBlue.opacity(0.08) : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(recording ? skyBlue : Color.primary.opacity(0.12), lineWidth: 1))
        }.buttonStyle(.plain).help("Click to record \(action.title.lowercased()); press Escape to cancel")
            .accessibilityLabel("\(action.title) shortcut").accessibilityValue(recording ? "Recording" : app.shortcut(for: action).display)
            .background(ShortcutKeyCapture(recording: recording, onKey: { event in
                if event.keyCode == 53 { app.endShortcutRecording(); return }
                app.setShortcut(CaptureShortcut(event: event), for: action)
            }, onResign: {
                if app.recordingAction == action { app.endShortcutRecording() }
            }).frame(width: 1, height: 1))
    }
}
private struct ShortcutKeyCapture: NSViewRepresentable {
    let recording: Bool
    let onKey: (NSEvent) -> Void
    let onResign: () -> Void
    func makeNSView(context: Context) -> KeyView { KeyView() }
    func updateNSView(_ view: KeyView, context: Context) {
        view.onKey = onKey; view.onResign = onResign; view.recording = recording
        if recording {
            DispatchQueue.main.async { [weak view] in guard let view, view.recording else { return }; view.window?.makeFirstResponder(view) }
        } else if view.window?.firstResponder === view { view.window?.makeFirstResponder(nil) }
    }
    final class KeyView: NSView {
        var recording = false
        var onKey: ((NSEvent) -> Void)?
        var onResign: (() -> Void)?
        override var acceptsFirstResponder: Bool { true }
        override func keyDown(with event: NSEvent) { if recording { onKey?(event) } else { super.keyDown(with: event) } }
        override func performKeyEquivalent(with event: NSEvent) -> Bool {
            guard recording, window?.firstResponder === self else { return false }
            onKey?(event); return true
        }
        override func resignFirstResponder() -> Bool {
            if recording { DispatchQueue.main.async { [weak self] in self?.onResign?() } }
            return super.resignFirstResponder()
        }
    }
}
