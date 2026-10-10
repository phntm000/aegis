// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisCrypto",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "AegisCrypto", targets: ["AegisCrypto"]),
    ],
    targets: [
        .target(
            name: "AegisCrypto",
            path: "Sources/AegisCrypto"
        ),
        .testTarget(
            name: "AegisCryptoTests",
            dependencies: ["AegisCrypto"],
            path: "Tests/AegisCryptoTests"
        ),
    ]
)
