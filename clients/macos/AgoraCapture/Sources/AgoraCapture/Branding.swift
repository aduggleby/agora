import AppKit
import SwiftUI

let skyBlue = Color(red: 14 / 255, green: 165 / 255, blue: 233 / 255)

enum CaptureBrand {
    static let blue = NSColor(srgbRed: 14 / 255, green: 165 / 255, blue: 233 / 255, alpha: 1)
    static func focusMark(in context: CGContext, rect: CGRect, color: NSColor) {
        context.saveGState()
        context.translateBy(x: rect.minX, y: rect.minY)
        context.scaleBy(x: rect.width / 100, y: rect.height / 100)
        context.setStrokeColor(color.cgColor); context.setFillColor(color.cgColor)
        context.setLineWidth(8); context.setLineCap(.round); context.setLineJoin(.round)
        for points in [
            [CGPoint(x: 15, y: 35), CGPoint(x: 15, y: 15), CGPoint(x: 35, y: 15)],
            [CGPoint(x: 65, y: 15), CGPoint(x: 85, y: 15), CGPoint(x: 85, y: 35)],
            [CGPoint(x: 85, y: 65), CGPoint(x: 85, y: 85), CGPoint(x: 65, y: 85)],
            [CGPoint(x: 35, y: 85), CGPoint(x: 15, y: 85), CGPoint(x: 15, y: 65)]
        ] {
            context.move(to: points[0]); for point in points.dropFirst() { context.addLine(to: point) }; context.strokePath()
        }
        context.fillEllipse(in: CGRect(x: 40, y: 40, width: 20, height: 20))
        context.restoreGState()
    }
    static var menuIcon: NSImage {
        let image = NSImage(size: CGSize(width: 18, height: 18), flipped: false) { rect in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            focusMark(in: context, rect: rect, color: .white)
            return true
        }
        image.isTemplate = false
        image.accessibilityDescription = "Agora Capture"
        return image
    }
}

struct CaptureActionStyle: ButtonStyle {
    var primary = false
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.colorScheme) private var colorScheme
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(primary ? Color.white : (colorScheme == .dark ? Color(red: 0.49, green: 0.83, blue: 0.98) : Color(red: 0.02, green: 0.36, blue: 0.55)))
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(skyBlue.opacity(configuration.isPressed ? 0.32 : (primary ? 1 : 0.10)), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(skyBlue.opacity(primary ? 0 : 0.24), lineWidth: 1))
            .opacity(!isEnabled ? 0.4 : (configuration.isPressed ? 0.8 : 1))
    }
}
