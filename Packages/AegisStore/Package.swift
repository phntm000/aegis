// swift-tools-version: 5.9
//  AegisStore — encrypted local persistence for the Aegis iOS client.
//
//  Ships the data models, the repository protocols the app codes against,
//  an in-memory implementation (tests, SwiftUI previews), and the SQLCipher
//  integration design doc (Sources/AegisStore/Docs/SQLCIPHER.md).
//
//  The production SQLCipher adapter is intentionally a *specified protocol*
//  (see Repositories.swift: SQLCipherStoreDescriptor), not a compiled
//  dependency here: SQLCipher/GRDB are added via Xcode/SPM in the app
//  target per Docs/SQLCIPHER.md, keeping this package dependency-free and
//  testable on any Swift toolchain.

import PackageDescription

let package = Package(
    name: "AegisStore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "AegisStore", targets: ["AegisStore"]),
    ],
    targets: [
        .target(
            name: "AegisStore",
            path: "Sources/AegisStore",
            // Docs/ is intentionally excluded from compilation; it ships
            // alongside the target for reference.
            exclude: ["Docs"]
        ),
        .testTarget(
            name: "AegisStoreTests",
            dependencies: ["AegisStore"],
            path: "Tests/AegisStoreTests"
        ),
    ]
)
