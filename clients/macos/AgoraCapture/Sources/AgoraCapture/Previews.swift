import AppKit
import SwiftUI

@MainActor func renderPreviews(app: CaptureApp, directory: String) throws {
    let folder = URL(fileURLWithPath: directory)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    func render<V: View>(_ view: V, size: CGSize, name: String, windowChrome: Bool = false) throws {
        let host = NSHostingView(rootView: view.background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light))
        host.frame = CGRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: host.frame, styleMask: windowChrome ? [.titled, .closable, .miniaturizable, .resizable] : [.borderless], backing: .buffered, defer: false)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        let surface = windowChrome ? (host.superview ?? host) : host
        surface.layoutSubtreeIfNeeded()
        guard let bitmap = surface.bitmapImageRepForCachingDisplay(in: surface.bounds) else { return }
        surface.cacheDisplay(in: surface.bounds, to: bitmap)
        guard let data = bitmap.representation(using: .png, properties: [:]) else { return }
        try data.write(to: folder.appendingPathComponent(name))
    }
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 1440, pixelsHigh: 900, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSColor(srgbRed: 0.97, green: 0.95, blue: 0.91, alpha: 1).setFill(); NSRect(x: 0, y: 0, width: 1440, height: 900).fill()
    ("AGORA  /  MY SHARES" as NSString).draw(at: CGPoint(x: 75, y: 790), withAttributes: [.font: NSFont.systemFont(ofSize: 24, weight: .medium), .foregroundColor: NSColor.darkGray])
    ("Good things, shared simply." as NSString).draw(at: CGPoint(x: 75, y: 650), withAttributes: [.font: NSFont.systemFont(ofSize: 55, weight: .medium), .foregroundColor: NSColor.black])
    for i in 0..<3 {
        NSColor.white.setFill(); NSBezierPath(roundedRect: NSRect(x: 75 + 435 * i, y: 150, width: 400, height: 400), xRadius: 20, yRadius: 20).fill()
        (["Brand assets", "Project notes", "Capture feedback"][i] as NSString).draw(at: CGPoint(x: 105 + 435 * i, y: 460), withAttributes: [.font: NSFont.systemFont(ofSize: 29, weight: .medium), .foregroundColor: NSColor.black])
        ("Everything you need,\nright where you need it." as NSString).draw(in: CGRect(x: 105 + 435 * i, y: 285, width: 310, height: 110), withAttributes: [.font: NSFont.systemFont(ofSize: 25), .foregroundColor: NSColor.darkGray])
    }
    NSGraphicsContext.restoreGraphicsState()
    let image = NSImage(size: CGSize(width: 1440, height: 900)); image.addRepresentation(rep)
    let model = EditorModel(image: image)
    model.annotations = [Annotation(kind: .rectangle, frame: CGRect(x: 65, y: 340, width: 415, height: 420), colorIndex: 0), Annotation(kind: .callout, frame: CGRect(x: 530, y: 150, width: 550, height: 100), text: "Can we give this card more space?", tip: CGPoint(x: 460, y: 370))]
    if let exported = model.export() { try exported.write(to: folder.appendingPathComponent("agora-export.png")) }
    model.tool = .select; model.selected = model.annotations.last?.id
    try render(EditorView(model: model, app: app, close: {}), size: CGSize(width: 1100, height: 760), name: "agora-editor.png", windowChrome: true)
    try render(SettingsView(app: app), size: CGSize(width: 540, height: 590), name: "agora-settings.png")
    let link = RecentLink(url: URL(string: "https://example.com/s/a8c3f21d")!, token: "a8c3f21d", expiresAt: Date().addingTimeInterval(86400), createdAt: Date(), server: URL(string: "https://example.com")!)
    try render(ToastView(link: link, image: image, copy: {}, close: {}, hover: { _ in }), size: CGSize(width: 420, height: 160), name: "agora-toast.png")
}
