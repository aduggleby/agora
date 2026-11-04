import AppKit

@main struct RenderIcon {
    static func main() throws {
        let folder = URL(fileURLWithPath: CommandLine.arguments[1])
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        for size in [16, 32, 64, 128, 256, 512, 1024] {
            let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
            let context = NSGraphicsContext(bitmapImageRep: rep)!
            NSGraphicsContext.current = context
            let cg = context.cgContext
            let s = CGFloat(size)
            let tile = CGRect(x: s * 0.06, y: s * 0.06, width: s * 0.88, height: s * 0.88)
            cg.setFillColor(CaptureBrand.blue.cgColor)
            cg.addPath(CGPath(roundedRect: tile, cornerWidth: s * 0.20, cornerHeight: s * 0.20, transform: nil)); cg.fillPath()
            CaptureBrand.focusMark(in: cg, rect: CGRect(x: s * 0.23, y: s * 0.23, width: s * 0.54, height: s * 0.54), color: .white)
            let data = rep.representation(using: .png, properties: [:])!
            let names: [Int: [String]] = [16: ["icon_16x16.png"], 32: ["icon_16x16@2x.png", "icon_32x32.png"], 64: ["icon_32x32@2x.png"], 128: ["icon_128x128.png"], 256: ["icon_128x128@2x.png", "icon_256x256.png"], 512: ["icon_256x256@2x.png", "icon_512x512.png"], 1024: ["icon_512x512@2x.png"]]
            for name in names[size]! { try data.write(to: folder.appendingPathComponent(name)) }
        }
    }
}
