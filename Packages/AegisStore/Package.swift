// swift-tools-version: 5.9
//  AegisStore — encrypted local persistence for the Aegis iOS client.
//
//  Ships the data models, the repository protocols the app codes against,
//  an in-memory implementation (tests, SwiftUI previews), and the
//  SQLCipher-backed production adapter (`SQLCipherAegisStore`).
//
//  SQLCipher is vendored as the `CSQLCipher` C target: the amalgamation
//  (sqlite3.c / sqlite3.h, SQLCipher v4.19.0 / SQLite 3.53.4, generated from
//  the v4.19.0 release tag — never a moving master) is compiled with
//  SQLITE_HAS_CODEC + SQLCIPHER_CRYPTO_CC, so encryption is provided by
//  Apple's CommonCrypto with no extra dependency on Apple platforms.
//  See Sources/AegisStore/Docs/SQLCIPHER.md for the key management and
//  schema design.

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
            name: "CSQLCipher",
            path: "Sources/CSQLCipher",
            publicHeadersPath: "include",
            cSettings: [
                // Enable the SQLCipher codec.
                .define("SQLITE_HAS_CODEC"),
                // Use CommonCrypto (Apple platforms) as the crypto provider.
                .define("SQLCIPHER_CRYPTO_CC"),
                // Required: codec registration hooks (hard #error without).
                .define("SQLITE_EXTRA_INIT", to: "sqlcipher_extra_init"),
                .define("SQLITE_EXTRA_SHUTDOWN", to: "sqlcipher_extra_shutdown"),
                // Encrypted full-text search lives inside the same DB file.
                .define("SQLITE_ENABLE_FTS5"),
                // No loadable extensions in the encrypted store, ever.
                .define("SQLITE_OMIT_LOAD_EXTENSION"),
                .define("SQLITE_TEMP_STORE", to: "2"),
                .define("SQLITE_THREADSAFE", to: "1"),
                .define("SQLITE_DEFAULT_MEMSTATUS", to: "0"),
            ]
        ),
        .target(
            name: "AegisStore",
            dependencies: ["CSQLCipher"],
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
