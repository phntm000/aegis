// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisModeration",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "AegisModeration", targets: ["AegisModeration"]),
    ],
    targets: [
        .target(
            name: "AegisModeration",
            path: "Sources/AegisModeration"
        ),
        .testTarget(
            name: "AegisModerationTests",
            dependencies: ["AegisModeration"],
            path: "Tests/AegisModerationTests"
        ),
    ]
)
