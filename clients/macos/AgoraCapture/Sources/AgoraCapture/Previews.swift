import AppKit
import SwiftUI

@MainActor func renderPreviews(app: CaptureApp, directory: String) throws {
    let folder = URL(fileURLWithPath: directory)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    for (name, outcome) in [("approved", CallbackPage.Outcome.approved), ("declined", .declined), ("invalid", .invalid)] {
        try CallbackPage.html(outcome: outcome).write(to: folder.appendingPathComponent("agora-callback-\(name).html"), atomically: true, encoding: .utf8)
    }
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
    let menu = NSMenu()
    app.menuWillOpen(menu)
    try render(DocumentationMenuPreview(items: menu.items), size: CGSize(width: 350, height: 302), name: "agora-tray-menu.png")
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
    // Presentation-only fixtures; preview generation never makes API requests.
    app.connectedServer = URL(string: "https://example.com")!
    app.account = Account(email: "alex@example.com", displayName: "Alex", serverVersion: "0.10.0", maxFileSizeBytes: 5368709120, directLinkDurations: ["30m", "6h", "1d", "7d"])
    let model = EditorModel(image: image)
    model.annotations = [Annotation(kind: .rectangle, frame: CGRect(x: 65, y: 340, width: 415, height: 420), colorIndex: 0), Annotation(kind: .callout, frame: CGRect(x: 530, y: 150, width: 550, height: 100), text: "Can we give this card more space?", tip: CGPoint(x: 460, y: 370))]
    if let exported = model.export() { try exported.write(to: folder.appendingPathComponent("agora-export.png")) }
    model.tool = .select; model.selected = model.annotations.last?.id
    try render(EditorView(model: model, app: app, close: {}), size: CGSize(width: 1100, height: 760), name: "agora-editor.png", windowChrome: true)
    try render(SettingsView(app: app), size: CGSize(width: 540, height: 590), name: "agora-settings.png")
    let link = RecentLink(url: URL(string: "https://example.com/s/a8c3f21d")!, token: "a8c3f21d", expiresAt: Date().addingTimeInterval(86400), createdAt: Date(), server: URL(string: "https://example.com")!)
    try render(ToastView(link: link, image: image, copy: {}, close: {}, hover: { _ in }), size: CGSize(width: 420, height: 160), name: "agora-toast.png")
}

// Documentation-only menu preview, populated from the actual NSMenu entries.
private struct DocumentationMenuPreview: View {
    let items: [NSMenuItem]
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Image(nsImage: CaptureBrand.menuIcon).frame(width: 34, height: 28)
                    .background(Color.white.opacity(0.12), in: RoundedRectangle(cornerRadius: 5))
            }.padding(.horizontal, 18).frame(height: 32).background(Color(white: 0.17))
            HStack {
                Spacer(minLength: 14)
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                        if item.isSeparatorItem { Divider().padding(.vertical, 5).padding(.horizontal, 8) }
                        else {
                            HStack {
                                Text(item.title)
                                Spacer()
                                if item.hasSubmenu { Image(systemName: "chevron.right").font(.system(size: 10)) }
                            }.font(.system(size: 13)).foregroundStyle(item.action != nil || item.hasSubmenu ? Color.primary : Color.secondary)
                                .padding(.horizontal, 15).frame(height: 27)
                        }
                    }
                }.padding(.vertical, 6).frame(width: 280)
                    .background(Color(white: 0.97), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.black.opacity(0.13), lineWidth: 0.5))
                    .shadow(color: .black.opacity(0.16), radius: 10, y: 5)
            }.padding(.trailing, 12).padding(.top, 2)
            Spacer(minLength: 8)
        }.background(Color(red: 0.91, green: 0.93, blue: 0.95))
    }
}
