// swift-tools-version: 5.9
//  Aegis — root SwiftPM manifest.
//
//  Aggregates the three local library packages. Each package is developed
//  independently (see Packages/<name>/Package.swift); this manifest exposes
//  them as one `Aegis` umbrella library for consumers that want a single
//  import.
//
//  NOTE: SwiftPM cannot express the XcodeGen-built iOS app target
//  (Aegis/, project.yml); the app consumes these same packages via
//  XcodeGen's `packages:` mapping. Keep the package names here in sync
//  with project.yml.

import PackageDescription

let package = Package(
    name: "Aegis",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "Aegis", targets: ["Aegis"]),
    ],
    dependencies: [
        // Cryptographic primitives: X3DH, Double Ratchet, sealed sender,
        // group key management. Spec: docs/CRYPTO.md
        .package(name: "AegisCrypto", path: "Packages/AegisCrypto"),
        // Sealed-envelope relay protocol, LAN/mDNS + BLE transport, outbox.
        .package(name: "AegisTransport", path: "Packages/AegisTransport"),
        // Encrypted persistence: models, repository protocols, SQLCipher design.
        .package(name: "AegisStore", path: "Packages/AegisStore"),
    ],
    targets: [
        .target(
            name: "Aegis",
            dependencies: [
                .product(name: "AegisCrypto", package: "AegisCrypto"),
                .product(name: "AegisTransport", package: "AegisTransport"),
                .product(name: "AegisStore", package: "AegisStore"),
            ],
            path: "Sources/Aegis"
        ),
    ]
)
