// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisDeviceLink",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "AegisDeviceLink", targets: ["AegisDeviceLink"]),
    ],
    targets: [
        .target(
            name: "AegisDeviceLink",
            path: "Sources/AegisDeviceLink"
        ),
        .testTarget(
            name: "AegisDeviceLinkTests",
            dependencies: ["AegisDeviceLink"],
            path: "Tests/AegisDeviceLinkTests"
        ),
    ]
)
