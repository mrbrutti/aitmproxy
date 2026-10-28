// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Aitmproxy",
    platforms: [.macOS(.v26)],
    targets: [
        // The command-bus client (§4.10): NWConnection over loopback TCP,
        // newline-delimited JSON-RPC 2.0 / MCP. No UI, no main actor.
        .target(name: "AitmBusClient"),
        // Domain models, formatting, filters, fixtures. No SwiftUI, so tests run without the app.
        .target(name: "AitmproxyKit", dependencies: ["AitmBusClient"]),
        .executableTarget(
            name: "Aitmproxy",
            dependencies: ["AitmproxyKit", "AitmBusClient"],
            // App code runs on the main thread unless you say otherwise.
            swiftSettings: [.defaultIsolation(MainActor.self)]
        ),
        .testTarget(name: "AitmBusClientTests", dependencies: ["AitmBusClient"]),
        .testTarget(name: "AitmproxyKitTests", dependencies: ["AitmproxyKit"]),
    ]
)
