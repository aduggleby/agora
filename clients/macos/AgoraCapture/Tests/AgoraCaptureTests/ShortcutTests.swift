import XCTest
import AppKit
import Carbon
@testable import AgoraCapture

final class ShortcutTests: XCTestCase {
    func testLegacyPresetMigratesToTwoIndependentDefaults() {
        let suite = "AgoraCaptureTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertEqual(CaptureShortcut.load(.area, defaults: defaults).display, "⌃ ⇧ A")
        XCTAssertEqual(CaptureShortcut.load(.fullScreen, defaults: defaults).display, "⌃ ⇧ S")
        defaults.set(1, forKey: "shortcutPreset")
        XCTAssertEqual(CaptureShortcut.load(.area, defaults: defaults).display, "⌃ ⌥ ⇧ A")
        XCTAssertEqual(CaptureShortcut.load(.fullScreen, defaults: defaults).display, "⌃ ⌥ ⇧ S")
    }
    func testSavingAreaDoesNotChangeFullScreen() throws {
        let suite = "AgoraCaptureTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let custom = CaptureShortcut(keyCode: UInt32(kVK_ANSI_K), modifiers: UInt32(controlKey | optionKey), keyLabel: "K")
        defaults.set(try JSONEncoder().encode(custom), forKey: CaptureAction.area.preferenceKey)
        XCTAssertEqual(CaptureShortcut.load(.area, defaults: defaults), custom)
        XCTAssertEqual(CaptureShortcut.load(.fullScreen, defaults: defaults).display, "⌃ ⇧ S")
    }
    func testValidationRejectsTypingKeysAndMalformedStoredShortcuts() throws {
        for modifiers in [UInt32(0), UInt32(shiftKey)] {
            XCTAssertFalse(CaptureShortcut(keyCode: 0, modifiers: modifiers, keyLabel: "A").isValid)
        }
        XCTAssertTrue(CaptureShortcut(keyCode: 0, modifiers: UInt32(controlKey | shiftKey), keyLabel: "A").isValid)
        XCTAssertFalse(CaptureShortcut(keyCode: 999, modifiers: UInt32(controlKey), keyLabel: "A").isValid)
        XCTAssertFalse(CaptureShortcut(keyCode: 0, modifiers: UInt32(controlKey), keyLabel: "\n").isValid)
        let suite = "AgoraCaptureTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(try JSONEncoder().encode(CaptureShortcut(keyCode: 0, modifiers: 0, keyLabel: "A")), forKey: CaptureAction.area.preferenceKey)
        XCTAssertTrue(CaptureShortcut.load(.area, defaults: defaults).isValid)
    }
    @MainActor func testRecorderConvertsModifiersAndNamesFunctionKeys() throws {
        let event = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [.control, .shift], timestamp: 0, windowNumber: 0, context: nil, characters: "a", charactersIgnoringModifiers: "a", isARepeat: false, keyCode: UInt16(kVK_ANSI_A)))
        let shortcut = CaptureShortcut(event: event)
        XCTAssertEqual(shortcut.keyCode, UInt32(kVK_ANSI_A))
        XCTAssertEqual(shortcut.display, "⌃ ⇧ A")
        let function = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [.control], timestamp: 0, windowNumber: 0, context: nil, characters: "", charactersIgnoringModifiers: "", isARepeat: false, keyCode: UInt16(kVK_F5)))
        XCTAssertEqual(CaptureShortcut(event: function).display, "⌃ F5")
    }
    @MainActor func testDuplicateAndInvalidShortcutLeaveBothActionsUnchanged() {
        let app = CaptureApp()
        let area = CaptureShortcut(keyCode: UInt32(kVK_ANSI_A), modifiers: UInt32(controlKey | shiftKey), keyLabel: "A")
        let screen = CaptureShortcut(keyCode: UInt32(kVK_ANSI_S), modifiers: UInt32(controlKey | shiftKey), keyLabel: "S")
        app.areaShortcut = area; app.screenShortcut = screen
        app.setShortcut(screen, for: .area)
        XCTAssertEqual(app.areaShortcut, area)
        XCTAssertEqual(app.screenShortcut, screen)
        XCTAssertNotNil(app.shortcutError)
        app.setShortcut(CaptureShortcut(keyCode: 0, modifiers: 0, keyLabel: "A"), for: .area)
        XCTAssertEqual(app.areaShortcut, area)
        XCTAssertNotNil(app.shortcutError)
    }
}
