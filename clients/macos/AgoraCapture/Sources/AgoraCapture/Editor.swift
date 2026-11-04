import AppKit
import SwiftUI

@MainActor final class EditorModel: ObservableObject {
    enum Tool: String, CaseIterable { case select = "Select", rectangle = "Rectangle", callout = "Callout" }
    let windowID = UUID().uuidString
    let image: NSImage
    let pixelSize: CGSize
    @Published var annotations: [Annotation] = []
    @Published var selected: UUID?
    @Published var tool: Tool = .rectangle
    @Published var nextColor = 0
    @Published var error: String?
    @Published var uploading = false
    @Published var uploadProgress: Double = 0
    @Published var retryAfter: Date?
    @Published var duration = UserDefaults.standard.string(forKey: "duration") ?? "1d"
    private var undoStack: [[Annotation]] = []
    private var redoStack: [[Annotation]] = []
    init(image: NSImage) {
        self.image = image
        let rep = image.representations.first!
        pixelSize = CGSize(width: rep.pixelsWide, height: rep.pixelsHigh)
    }
    func checkpoint() { undoStack.append(annotations); redoStack.removeAll() }
    func undo() { guard let state = undoStack.popLast() else { return }; redoStack.append(annotations); annotations = state }
    func redo() { guard let state = redoStack.popLast() else { return }; undoStack.append(annotations); annotations = state }
    func delete() { checkpoint(); annotations.removeAll { $0.id == selected }; selected = nil }
    func chooseColor(_ color: Int) {
        nextColor = color
        if let i = annotations.firstIndex(where: { $0.id == selected && $0.kind == .rectangle }) { checkpoint(); annotations[i].colorIndex = color }
    }
    func share<T>(using operation: () async throws -> T, onSuccess: (T) -> Void) async {
        guard !uploading else { return }
        error = nil; uploading = true; uploadProgress = 0; retryAfter = nil
        do {
            let result = try await operation()
            uploading = false
            onSuccess(result)
        } catch {
            uploading = false
            self.error = error.localizedDescription
            if let api = error as? APIError, let delay = api.retryAfter { retryAfter = Date().addingTimeInterval(delay) }
        }
    }
    func export() -> Data? {
        let width = Int(pixelSize.width), height = Int(pixelSize.height)
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0), let context = NSGraphicsContext(bitmapImageRep: rep) else { return nil }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        let cg = context.cgContext
        cg.translateBy(x: 0, y: CGFloat(height)); cg.scaleBy(x: 1, y: -1)
        NSGraphicsContext.current = NSGraphicsContext(cgContext: cg, flipped: true)
        image.draw(in: CGRect(origin: .zero, size: pixelSize), from: .zero, operation: .copy, fraction: 1, respectFlipped: true, hints: nil)
        drawAnnotations(cg, annotations: annotations, scale: 1)
        NSGraphicsContext.restoreGraphicsState()
        return rep.retagging(with: .sRGB)?.representation(using: .png, properties: [:])
    }
}
func drawAnnotations(_ context: CGContext, annotations: [Annotation], scale: CGFloat) {
    for a in annotations {
        context.saveGState()
        context.setLineWidth(6)
        if a.kind == .rectangle {
            context.setStrokeColor(CapturePalette.color(a.colorIndex).cgColor)
            context.stroke(a.frame)
        } else {
            let center = CGPoint(x: a.frame.midX, y: a.frame.midY)
            let dx = a.tip.x - center.x, dy = a.tip.y - center.y
            let divisor = max(abs(dx) / max(a.frame.width / 2, 1), abs(dy) / max(a.frame.height / 2, 1), 1)
            let edge = CGPoint(x: center.x + dx / divisor, y: center.y + dy / divisor)
            context.setStrokeColor(NSColor.black.cgColor)
            context.setFillColor(NSColor.black.cgColor)
            context.setLineWidth(4)
            context.move(to: edge); context.addLine(to: a.tip); context.strokePath()
            let angle = atan2(dy, dx), length: CGFloat = 20
            context.move(to: a.tip)
            context.addLine(to: CGPoint(x: a.tip.x - length * cos(angle - 0.45), y: a.tip.y - length * sin(angle - 0.45)))
            context.addLine(to: CGPoint(x: a.tip.x - length * cos(angle + 0.45), y: a.tip.y - length * sin(angle + 0.45)))
            context.closePath(); context.fillPath()
            let path = CGPath(roundedRect: a.frame, cornerWidth: 12, cornerHeight: 12, transform: nil)
            context.setFillColor(NSColor.white.cgColor); context.addPath(path); context.fillPath()
            context.addPath(path); context.strokePath()
            // AppKit text drawing honors the flipped canvas used by both preview and export.
            let text = a.text as NSString
            text.draw(in: a.frame.insetBy(dx: 18, dy: 14), withAttributes: [.font: NSFont.systemFont(ofSize: 30, weight: .medium), .foregroundColor: NSColor.black])
        }
        context.restoreGState()
    }
}
struct AnnotationCanvas: NSViewRepresentable {
    @ObservedObject var model: EditorModel
    func makeNSView(context: Context) -> DrawingView { DrawingView(model: model) }
    func updateNSView(_ view: DrawingView, context: Context) { view.refresh() }
}
enum ResizeHandle: CaseIterable {
    case topLeft, top, topRight, right, bottomRight, bottom, bottomLeft, left
    func point(in r: CGRect) -> CGPoint {
        switch self {
        case .topLeft: return CGPoint(x: r.minX, y: r.minY)
        case .top: return CGPoint(x: r.midX, y: r.minY)
        case .topRight: return CGPoint(x: r.maxX, y: r.minY)
        case .right: return CGPoint(x: r.maxX, y: r.midY)
        case .bottomRight: return CGPoint(x: r.maxX, y: r.maxY)
        case .bottom: return CGPoint(x: r.midX, y: r.maxY)
        case .bottomLeft: return CGPoint(x: r.minX, y: r.maxY)
        case .left: return CGPoint(x: r.minX, y: r.midY)
        }
    }
    func resize(_ r: CGRect, delta: CGSize, minimum: CGFloat = 30) -> CGRect {
        var x1 = r.minX, x2 = r.maxX, y1 = r.minY, y2 = r.maxY
        if [.topLeft, .left, .bottomLeft].contains(self) { x1 = min(x1 + delta.width, x2 - minimum) }
        if [.topRight, .right, .bottomRight].contains(self) { x2 = max(x2 + delta.width, x1 + minimum) }
        if [.topLeft, .top, .topRight].contains(self) { y1 = min(y1 + delta.height, y2 - minimum) }
        if [.bottomLeft, .bottom, .bottomRight].contains(self) { y2 = max(y2 + delta.height, y1 + minimum) }
        return CGRect(x: x1, y: y1, width: x2 - x1, height: y2 - y1)
    }
}
@MainActor final class DrawingView: NSView, NSTextViewDelegate {
    let model: EditorModel
    var start = CGPoint.zero
    var original = CGRect.zero
    var originalTip = CGPoint.zero
    var draggingTip = false
    var handle: ResizeHandle?
    var creating = false
    var active: UUID?
    var inlineEditor: NSTextView?
    var editingID: UUID?
    override var isFlipped: Bool { true }
    override var acceptsFirstResponder: Bool { true }
    init(model: EditorModel) { self.model = model; super.init(frame: .zero) }
    required init?(coder: NSCoder) { fatalError() }
    var scale: CGFloat { max(0.001, bounds.width / model.pixelSize.width) }
    func point(_ event: NSEvent) -> CGPoint { let p = convert(event.locationInWindow, from: nil); return CGPoint(x: p.x / scale, y: p.y / scale) }
    func refresh() {
        if let id = editingID, model.selected != id || !model.annotations.contains(where: { $0.id == id }) || model.uploading { endEditing() }
        positionEditor()
        needsDisplay = true
    }
    override func layout() { super.layout(); positionEditor() }
    func dragGrip(_ a: Annotation) -> CGRect {
        CGRect(x: a.frame.midX - 24 / scale, y: a.frame.minY - 27 / scale, width: 48 / scale, height: 16 / scale)
    }
    func positionEditor() {
        guard let id = editingID, let a = model.annotations.first(where: { $0.id == id }) else { return }
        let r = a.frame.insetBy(dx: 18, dy: 14)
        inlineEditor?.frame = CGRect(x: r.minX * scale, y: r.minY * scale, width: r.width * scale, height: r.height * scale)
        inlineEditor?.font = .systemFont(ofSize: 30 * scale, weight: .medium)
    }
    func beginEditing(_ id: UUID) {
        endEditing()
        guard let a = model.annotations.first(where: { $0.id == id && $0.kind == .callout }) else { return }
        model.checkpoint()
        let editor = NSTextView(frame: .zero)
        editor.allowsUndo = true; editor.isRichText = false; editor.drawsBackground = true; editor.backgroundColor = .white; editor.textColor = .black
        editor.textContainerInset = .zero; editor.textContainer?.lineFragmentPadding = 0
        editor.isHorizontallyResizable = false; editor.isVerticallyResizable = false
        editor.autoresizingMask = []; editor.string = a.text; editor.delegate = self
        editor.setAccessibilityLabel("Comment text")
        inlineEditor = editor; editingID = id; addSubview(editor); positionEditor()
        window?.makeFirstResponder(editor)
        if a.text == "Add a comment" { editor.selectAll(nil) }
    }
    func textDidChange(_ notification: Notification) {
        guard let id = editingID, let editor = inlineEditor, let i = model.annotations.firstIndex(where: { $0.id == id }) else { return }
        model.annotations[i].text = editor.string
    }
    func textView(_ textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        if commandSelector == #selector(NSResponder.cancelOperation(_:)) { endEditing(); return true }
        return false
    }
    func endEditing() {
        guard let editor = inlineEditor else { return }
        if let id = editingID, let i = model.annotations.firstIndex(where: { $0.id == id }) { model.annotations[i].text = editor.string }
        inlineEditor = nil; editingID = nil; editor.delegate = nil
        window?.makeFirstResponder(self); editor.removeFromSuperview(); needsDisplay = true
    }
    override func draw(_ dirtyRect: NSRect) {
        guard let c = NSGraphicsContext.current?.cgContext else { return }
        c.saveGState(); c.scaleBy(x: scale, y: scale)
        model.image.draw(in: CGRect(origin: .zero, size: model.pixelSize), from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
        drawAnnotations(c, annotations: model.annotations, scale: scale)
        if let a = model.annotations.first(where: { $0.id == model.selected }) {
            c.setStrokeColor(NSColor.controlAccentColor.cgColor); c.setLineWidth(1.5 / scale)
            c.setLineDash(phase: 0, lengths: [5 / scale, 4 / scale]); c.stroke(a.frame.insetBy(dx: -5 / scale, dy: -5 / scale)); c.setLineDash(phase: 0, lengths: [])
            for h in ResizeHandle.allCases {
                let p = h.point(in: a.frame)
                let r = CGRect(x: p.x - 4 / scale, y: p.y - 4 / scale, width: 8 / scale, height: 8 / scale)
                c.setFillColor(NSColor.white.cgColor); c.fill(r); c.stroke(r)
            }
            if a.kind == .callout {
                c.setFillColor(NSColor.controlAccentColor.cgColor)
                c.addPath(CGPath(roundedRect: dragGrip(a), cornerWidth: 5 / scale, cornerHeight: 5 / scale, transform: nil)); c.fillPath()
                c.setFillColor(NSColor.white.cgColor)
                for offset in [-8.0, 0, 8.0] {
                    c.fillEllipse(in: CGRect(x: a.frame.midX + CGFloat(offset - 1.5) / scale, y: a.frame.minY - 20.5 / scale, width: 3 / scale, height: 3 / scale))
                }
                c.setFillColor(NSColor.controlAccentColor.cgColor)
                c.fillEllipse(in: CGRect(x: a.tip.x - 6 / scale, y: a.tip.y - 6 / scale, width: 12 / scale, height: 12 / scale))
            }
        }
        c.restoreGState()
    }
    override func keyDown(with event: NSEvent) {
        guard !model.uploading else { return }
        if event.modifierFlags.contains(.command), event.charactersIgnoringModifiers == "z" {
            if event.modifierFlags.contains(.shift) { model.redo() } else { model.undo() }
        } else if event.keyCode == 51 || event.keyCode == 117 { model.delete() }
        else if event.keyCode == 53 { window?.close() }
        else { super.keyDown(with: event) }
    }
    override func mouseDown(with event: NSEvent) {
        guard !model.uploading else { return }
        endEditing(); window?.makeFirstResponder(self)
        start = point(event); draggingTip = false; handle = nil; creating = false
        // Selected handles win over overlapping annotations and the drawing tool.
        let selected = model.annotations.first(where: { $0.id == model.selected })
        if let a = selected { handle = ResizeHandle.allCases.first { hypot($0.point(in: a.frame).x - start.x, $0.point(in: a.frame).y - start.y) < 10 / scale } }
        let gripHit = selected.map { $0.kind == .callout && dragGrip($0).contains(start) } ?? false
        let hit = handle != nil || gripHit ? selected : model.annotations.reversed().first { a in
            let tipHit = a.kind == .callout && hypot(a.tip.x - start.x, a.tip.y - start.y) < 14 / scale
            return a.frame.insetBy(dx: -6 / scale, dy: -6 / scale).contains(start) || tipHit
        }
        if let a = hit, model.tool == .select || a.id == model.selected || a.kind == .callout {
            model.selected = a.id; active = a.id; original = a.frame; originalTip = a.tip
            draggingTip = a.kind == .callout && hypot(a.tip.x - start.x, a.tip.y - start.y) < 14 / scale
            if event.clickCount == 2 && a.kind == .callout && !draggingTip && handle == nil { active = nil; beginEditing(a.id); return }
            model.checkpoint()
        } else if model.tool != .select {
            model.checkpoint(); creating = true
            let isRect = model.tool == .rectangle
            let a = Annotation(kind: isRect ? .rectangle : .callout, frame: CGRect(origin: start, size: isRect ? .zero : CGSize(width: 480, height: 120)), colorIndex: model.nextColor, tip: CGPoint(x: start.x + 100, y: start.y + 200))
            model.annotations.append(a); active = a.id; model.selected = a.id
            if isRect { model.nextColor = CapturePalette.next(model.nextColor) }
        } else { model.selected = nil; active = nil }
        needsDisplay = true
    }
    override func mouseDragged(with event: NSEvent) {
        guard let i = model.annotations.firstIndex(where: { $0.id == active }) else { return }
        let p = point(event), dx = p.x - start.x, dy = p.y - start.y
        if creating {
            if model.annotations[i].kind == .rectangle { model.annotations[i].frame = CGRect(x: min(start.x, p.x), y: min(start.y, p.y), width: abs(dx), height: abs(dy)) }
            else { model.annotations[i].frame.origin = p }
        } else if draggingTip { model.annotations[i].tip = p }
        else if let handle { model.annotations[i].frame = handle.resize(original, delta: CGSize(width: dx, height: dy), minimum: model.annotations[i].kind == .callout ? 80 : 30) }
        else {
            // Moving a comment leaves its arrow pointing at the referenced item.
            model.annotations[i].frame = original.offsetBy(dx: dx, dy: dy)
        }
        needsDisplay = true
    }
    override func mouseUp(with event: NSEvent) {
        let createdCallout = creating ? model.annotations.first(where: { $0.id == active && $0.kind == .callout })?.id : nil
        model.annotations.removeAll { $0.kind == .rectangle && ($0.frame.width < 3 || $0.frame.height < 3) }
        active = nil; creating = false; needsDisplay = true
        if let id = createdCallout { model.tool = .select; beginEditing(id) }
    }
}
struct EditorView: View {
    @ObservedObject var model: EditorModel
    @ObservedObject var app: CaptureApp
    let close: () -> Void
    private var canvasBackground: Color { Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? NSColor(white: 0.13, alpha: 1) : NSColor(white: 0.98, alpha: 1)
    }) }
    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 0) {
                VStack(spacing: 12) {
                    toolButton(.select, symbol: "cursorarrow", help: "Select and move annotations")
                    toolButton(.rectangle, symbol: "rectangle", help: "Draw a rectangle")
                    toolButton(.callout, symbol: "text.bubble", help: "Add a comment; double-click to edit inline")
                    Divider().padding(.horizontal, 12).padding(.vertical, 4)
                    railButton("arrow.uturn.backward", help: "Undo (Command-Z)", action: model.undo)
                    railButton("arrow.uturn.forward", help: "Redo (Command-Shift-Z)", action: model.redo)
                    Spacer()
                }.padding(.top, 14).frame(width: 62)
                GeometryReader { geo in
                    let s = max(0.001, min((geo.size.width - 64) / model.pixelSize.width, (geo.size.height - 64) / model.pixelSize.height))
                    AnnotationCanvas(model: model)
                        .frame(width: model.pixelSize.width * s, height: model.pixelSize.height * s)
                        .shadow(color: .black.opacity(0.06), radius: 12, y: 3)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }.background(canvasBackground).clipShape(RoundedRectangle(cornerRadius: 8))
            }.padding(.trailing, 20)
            if let error = model.error { Text(error).foregroundStyle(.red).font(.callout).padding(10) }
            HStack(spacing: 12) {
                Text(model.tool == .callout ? "Comment" : "Rectangle").font(.caption).foregroundStyle(.secondary).frame(width: 62, alignment: .leading)
                HStack(spacing: 4) {
                    ForEach(0..<10) { i in
                        Button { model.chooseColor(i) } label: {
                            Circle().fill(Color(nsColor: CapturePalette.color(i)))
                                .frame(width: 12, height: 12).padding(4)
                                .overlay(Circle().stroke(model.nextColor == i ? Color.primary.opacity(0.6) : .clear, lineWidth: 1))
                        }.buttonStyle(.plain).help(CapturePalette.names[i]).accessibilityLabel(CapturePalette.names[i])
                    }
                }.opacity(model.tool == .callout ? 0.35 : 1)
                Spacer(minLength: 12)
                Button("Save…", action: save).buttonStyle(CaptureActionStyle())
                Button("Copy image") {
                    if let data = model.export(), let image = NSImage(data: data) { NSPasteboard.general.clearContents(); NSPasteboard.general.writeObjects([image]) }
                }.buttonStyle(CaptureActionStyle())
                Button("Cancel", action: close).buttonStyle(CaptureActionStyle()).help("Close this capture without uploading")
                Button("Delete", action: model.delete).buttonStyle(CaptureActionStyle())
                    .disabled(model.selected == nil).help(model.selected == nil ? "Select a rectangle or comment to delete it" : "Delete the selected annotation (Backspace)")
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let wait = max(0, Int(ceil(model.retryAfter?.timeIntervalSince(context.date) ?? 0)))
                    Button(model.uploading ? (model.uploadProgress < 1 ? "Uploading \(Int(model.uploadProgress * 100))%" : "Creating link…") : (wait > 0 ? "Retry in \(wait)s" : (app.account == nil ? "Connect…" : "Share link"))) {
                        if app.account == nil { app.showSettings() }
                        else { Task { await upload() } }
                    }.keyboardShortcut(.return, modifiers: .command).buttonStyle(CaptureActionStyle(primary: true))
                        .disabled(wait > 0 && app.account != nil).help(wait > 0 ? "Wait for the server's retry interval before uploading again" : "Create a temporary image link")
                }
                if app.durations.isEmpty {
                    Text("Not connected").font(.caption).foregroundStyle(.secondary)
                } else {
                    HStack(spacing: 8) {
                        Text("Keep for").foregroundStyle(.secondary).fixedSize()
                        Picker("Keep for", selection: $model.duration) {
                            ForEach(app.durations, id: \.self) { Text(durationLabel($0)).tag($0) }
                        }.labelsHidden().frame(width: 108).help("How long the uploaded image link remains available")
                    }
                }


            }.font(.system(size: 12)).padding(.horizontal, 22).padding(.vertical, 18)
        }.tint(skyBlue).background(Color(nsColor: .windowBackgroundColor)).disabled(model.uploading).frame(minWidth: 1000, minHeight: 580)
        .onAppear { reconcileDuration() }
        .onChange(of: app.durations) { _, _ in reconcileDuration() }
    }
    private func reconcileDuration() {
        if !app.durations.contains(model.duration), let first = app.durations.first { model.duration = first }
    }
    private func toolButton(_ tool: EditorModel.Tool, symbol: String, help: String) -> some View {
        Button { model.tool = tool } label: {
            Image(systemName: symbol).font(.system(size: 17)).frame(width: 40, height: 38)
                .background(model.tool == tool ? skyBlue.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 9))
        }.buttonStyle(.plain).help(help).accessibilityLabel(tool.rawValue).accessibilityAddTraits(model.tool == tool ? [.isSelected] : [])
    }
    private func railButton(_ symbol: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Image(systemName: symbol).font(.system(size: 15)).frame(width: 40, height: 30) }
            .buttonStyle(.plain).foregroundStyle(.secondary).help(help).accessibilityLabel(help)
    }
    func save() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.png]; panel.nameFieldStringValue = "Agora Capture.png"
        if panel.runModal() == .OK, let url = panel.url { do { guard let data = model.export() else { return }; try data.write(to: url, options: .atomic) } catch { model.error = error.localizedDescription } }
    }
    func upload() async {
        await model.share(using: {
            guard let png = model.export() else { throw ClientError(message: "Could not render this capture.") }
            let link = try await app.upload(png, duration: model.duration) { progress in
                Task { @MainActor in model.uploadProgress = progress }
            }
            return (link, png)
        }, onSuccess: { link, png in
            UserDefaults.standard.set(model.duration, forKey: "duration")
            // Dismiss the source editor before presenting the success toast.
            close()
            if let image = NSImage(data: png) { app.showToast(link, image: image) }
        })
    }
}
