// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TunnelCatSDK",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "TunnelCatSDK", targets: ["TunnelCatSDK"]),
    ],
    targets: [
        .target(name: "TunnelCatSDK"),
        .executableTarget(name: "Basic", dependencies: ["TunnelCatSDK"], path: "Examples/Basic"),
    ]
)
