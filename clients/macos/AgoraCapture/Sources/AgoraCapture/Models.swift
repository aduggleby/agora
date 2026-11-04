import AppKit
import SwiftUI

struct Annotation: Identifiable, Equatable {
    enum Kind: String { case rectangle, callout }
    var id = UUID()
    var kind: Kind
    var frame: CGRect
    var colorIndex = 0
    var text = "Add a comment"
    var tip: CGPoint = .zero
}
struct RecentLink: Codable, Identifiable {
    var id: String { server.absoluteString + "/" + token }
    let url: URL
    let token: String
    let expiresAt: Date
    let createdAt: Date
    let server: URL
}
struct Account: Decodable {
    let email: String
    let displayName: String?
    let serverVersion: String
    let maxFileSizeBytes: Int64
    let directLinkDurations: [String]
}
struct UploadReply: Decodable {
    let url: URL
    let token: String
    let expiresAtUtc: Date
}
enum CapturePalette {
    static let names = ["Red", "Green", "Blue", "Yellow", "Orange", "Purple", "Pink", "Cyan", "Brown", "Black"]
    static let hex = [0xE5322D, 0x22A447, 0x2474E8, 0xF5CF00, 0xF7811E, 0x8B45C6, 0xE8418C, 0x00B8CC, 0x925A32, 0x1D1D1F]
    static func color(_ index: Int) -> NSColor {
        let h = hex[((index % 10) + 10) % 10]
        return NSColor(srgbRed: CGFloat((h >> 16) & 255) / 255, green: CGFloat((h >> 8) & 255) / 255, blue: CGFloat(h & 255) / 255, alpha: 1)
    }
    static func next(_ index: Int) -> Int { (index + 1) % 10 }
}
func durationLabel(_ value: String) -> String {
    ["30m": "30 minutes", "6h": "6 hours", "1d": "1 day", "7d": "7 days"][value] ?? value
}
