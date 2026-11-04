import XCTest
@testable import AgoraCapture

final class CaptureTests: XCTestCase {
    func testPKCERFC7636Vector() {
        XCTAssertEqual(PKCE.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }
    func testRandomVerifierIsURLSafeAndUnique() throws {
        let a = try PKCE.random(32), b = try PKCE.random(32)
        XCTAssertEqual(a.count, 43); XCTAssertNotEqual(a, b)
        XCTAssertNil(a.rangeOfCharacter(from: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_").inverted))
    }
    func testServerValidation() throws {
        XCTAssertNoThrow(try AgoraClient.serverURL("https://files.example.com"))
        XCTAssertNoThrow(try AgoraClient.serverURL("http://127.0.0.1:18080"))
        for value in ["http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?x=1", "file:///etc/passwd"] {
            XCTAssertThrowsError(try AgoraClient.serverURL(value))
        }
    }
    func testPaletteWraps() { XCTAssertEqual(CapturePalette.next(9), 0); XCTAssertEqual(CapturePalette.next(0), 1) }
    func testServerDatesWithAndWithoutFractionalSeconds() throws {
        for date in ["2026-11-04T18:00:00Z", "2026-11-04T18:00:00.1234567Z"] {
            let json = Data("{\"url\":\"https://example.com/s/a\",\"token\":\"a\",\"expiresAtUtc\":\"\(date)\"}".utf8)
            XCTAssertNoThrow(try AgoraClient.decoder.decode(UploadReply.self, from: json))
        }
    }
    @MainActor func testExportPreservesPixelsAndUndoRestoresAnnotations() throws {
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 240, pixelsHigh: 160, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        let image = NSImage(size: NSSize(width: 120, height: 80)); image.addRepresentation(rep)
        let model = EditorModel(image: image)
        model.checkpoint()
        model.annotations = [Annotation(kind: .rectangle, frame: CGRect(x: 30, y: 30, width: 80, height: 60))]
        let data = try XCTUnwrap(model.export())
        let exported = try XCTUnwrap(NSBitmapImageRep(data: data))
        XCTAssertEqual(exported.pixelsWide, 240); XCTAssertEqual(exported.pixelsHigh, 160)
        model.undo(); XCTAssertTrue(model.annotations.isEmpty)
        model.redo(); XCTAssertEqual(model.annotations.count, 1)
    }
    @MainActor func testExportDoesNotFlipImageOrAnnotation() throws {
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 100, pixelsHigh: 100, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        for y in 0..<100 { for x in 0..<100 {
            let offset = y * rep.bytesPerRow + x * 4
            for channel in 0..<3 { rep.bitmapData![offset + channel] = y < 50 ? 255 : 0 }
            rep.bitmapData![offset + 3] = 255
        } }

        let image = NSImage(size: NSSize(width: 100, height: 100)); image.addRepresentation(rep)
        let model = EditorModel(image: image)
        model.annotations = [Annotation(kind: .rectangle, frame: CGRect(x: 10, y: 10, width: 30, height: 20))]
        let exported = try XCTUnwrap(NSBitmapImageRep(data: XCTUnwrap(model.export())))
        XCTAssertGreaterThan(exported.colorAt(x: 80, y: 10)!.redComponent, 0.9)
        XCTAssertLessThan(exported.colorAt(x: 80, y: 90)!.redComponent, 0.1)
        let stroke = exported.colorAt(x: 10, y: 20)!
        XCTAssertGreaterThan(stroke.redComponent, 0.7)
        XCTAssertLessThan(stroke.greenComponent, 0.4)
    }

    func testResizeHandlesKeepOppositeEdgeAnchoredAndClamp() {
        let r = CGRect(x: 100, y: 100, width: 200, height: 100)
        XCTAssertEqual(ResizeHandle.topLeft.resize(r, delta: CGSize(width: -20, height: -10)), CGRect(x: 80, y: 90, width: 220, height: 110))
        XCTAssertEqual(ResizeHandle.right.resize(r, delta: CGSize(width: 50, height: 900)), CGRect(x: 100, y: 100, width: 250, height: 100))
        XCTAssertEqual(ResizeHandle.bottom.resize(r, delta: CGSize(width: 900, height: 50)), CGRect(x: 100, y: 100, width: 200, height: 150))
        for handle in ResizeHandle.allCases {
            let result = handle.resize(r, delta: CGSize(width: 1000, height: 1000))
            XCTAssertGreaterThanOrEqual(result.width, 30)
            XCTAssertGreaterThanOrEqual(result.height, 30)
        }
    }
    @MainActor func testInlineCommentChangesModelAndUndoRestoresText() {
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 800, pixelsHigh: 600, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        let image = NSImage(size: CGSize(width: 800, height: 600)); image.addRepresentation(rep)
        let model = EditorModel(image: image)
        let comment = Annotation(kind: .callout, frame: CGRect(x: 20, y: 20, width: 300, height: 100))
        model.annotations = [comment]; model.selected = comment.id
        let view = DrawingView(model: model); view.frame.size = CGSize(width: 400, height: 300)
        view.beginEditing(comment.id)
        XCTAssertEqual(view.inlineEditor?.frame.origin, CGPoint(x: 19, y: 17))
        view.inlineEditor?.string = "Edited directly on the image"
        view.textDidChange(Notification(name: NSText.didChangeNotification))
        XCTAssertEqual(model.annotations[0].text, "Edited directly on the image")
        view.endEditing()
        XCTAssertNil(view.inlineEditor)
        model.undo()
        XCTAssertEqual(model.annotations[0].text, "Add a comment")
    }

    @MainActor func testSuccessfulShareClosesOnlyAfterUploadCompletes() async {
        let model = EditorModel(image: fixtureImage())
        var closed = false
        await model.share(using: {
            XCTAssertTrue(model.uploading)
            XCTAssertFalse(closed)
            return "shared-link"
        }, onSuccess: { result in
            XCTAssertEqual(result, "shared-link")
            XCTAssertFalse(model.uploading)
            closed = true
        })
        XCTAssertTrue(closed)
    }
    @MainActor func testFailedShareKeepsEditorAndAnnotationsForRetry() async {
        let model = EditorModel(image: fixtureImage())
        let annotation = Annotation(kind: .rectangle, frame: CGRect(x: 5, y: 5, width: 40, height: 40))
        model.annotations = [annotation]
        var closed = false
        await model.share(using: { () async throws -> String in
            throw APIError(status: 503, retryAfter: 5)
        }, onSuccess: { _ in closed = true })
        XCTAssertFalse(closed)
        XCTAssertFalse(model.uploading)
        XCTAssertEqual(model.annotations, [annotation])
        XCTAssertNotNil(model.error)
        XCTAssertNotNil(model.retryAfter)
    }
    @MainActor func testCloseEditorReleasesOnlyTheMatchingWindow() {
        _ = NSApplication.shared
        let app = CaptureApp()
        let window = NSWindow(contentRect: CGRect(x: 0, y: 0, width: 200, height: 200), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.identifier = NSUserInterfaceItemIdentifier("shared-editor")
        window.delegate = app
        window.contentView = NSView()
        app.editorWindows = [window]
        app.closeEditor("unrelated-editor")
        XCTAssertEqual(app.editorWindows.count, 1)
        app.closeEditor("shared-editor")
        XCTAssertFalse(window.isVisible)
        XCTAssertTrue(app.editorWindows.isEmpty)
        XCTAssertNil(window.contentView)
    }
    @MainActor private func fixtureImage() -> NSImage {
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 100, pixelsHigh: 100, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        let image = NSImage(size: CGSize(width: 100, height: 100)); image.addRepresentation(rep)
        return image
    }

}
