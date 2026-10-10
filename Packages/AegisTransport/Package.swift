// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisTransport",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "AegisTransport", targets: ["AegisTransport"]),
    ],
    targets: [
        .target(
            name: "AegisTransport",
            path: "Sources/AegisTransport"
        ),
        .testTarget(
            name: "AegisTransportTests",
            dependencies: ["AegisTransport"],
            path: "Tests/AegisTransportTests"
        ),
    ]
)
