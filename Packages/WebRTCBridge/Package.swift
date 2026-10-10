// swift-tools-version: 5.9
//  WebRTCBridge — SwiftPM access to the WebRTC native framework plus small
//  pure-Swift helpers used by the app's media layer.
//
//  The native framework is NOT vendored in git: it is fetched by Xcode /
//  SwiftPM at build time from the pinned release below (45 MB). The URL and
//  checksum are pinned to a specific upstream release so builds are
//  reproducible; bump both together when moving to a newer milestone.
//
//  Upstream: stasel/WebRTC — community SwiftPM distribution of Google's
//  official WebRTC iOS builds (BSD-3-Clause, same license as WebRTC
//  itself). M154 includes ios-arm64 (device) and ios-x86_64_arm64-simulator
//  slices, so both device and CI simulator builds link. Requires iOS 15+;
//  this package targets iOS 17 to match the app.

import PackageDescription

let package = Package(
    name: "WebRTCBridge",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "WebRTCBridge", targets: ["WebRTCBridge"]),
    ],
    targets: [
        .binaryTarget(
            name: "WebRTC",
            url: "https://github.com/stasel/WebRTC/releases/download/154.0.0/WebRTC-M154.xcframework.zip",
            checksum: "a2bcdda93578c82452ceb6e49d54a2746e1bcb4caf7c2fa601ffac8028b58c16"
        ),
        .target(
            name: "WebRTCBridge",
            dependencies: ["WebRTC"]
        ),
    ]
)
