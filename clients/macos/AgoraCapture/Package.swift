// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AgoraCapture",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "AgoraCapture", targets: ["AgoraCapture"])],
    targets: [
        .executableTarget(name: "AgoraCapture"),
        .testTarget(name: "AgoraCaptureTests", dependencies: ["AgoraCapture"])
    ],
    swiftLanguageModes: [.v5]
)
