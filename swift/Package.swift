// swift-tools-version:5.9
import PackageDescription

// RoomWire: the wire format and the decisions made about it, and the transport
// that carries it.
//
// Two products, and the split between them is the point. `RoomWireProtocol` has
// no platform inside and no dependency outside: plain value types whose only
// clock is a `TimeInterval` the caller passes in, which is what lets every
// check run in about a second with no device and no second machine.
// `RoomWireTransport` is where the sockets, the keychain and the radio live.
//
// Swift 5 language mode on purpose: the consuming app builds in it.
let package = Package(
    name: "RoomWire",
    platforms: [.macOS("15.0"), .iOS("18.0")],
    products: [
        .library(name: "RoomWireProtocol", targets: ["RoomWireProtocol"]),
        .library(name: "RoomWireTransport", targets: ["RoomWireTransport"]),
        .executable(name: "roomwire-lab", targets: ["RoomWireLab"]),
    ],
    dependencies: [
        // Minting a self-signed certificate is the one thing neither CryptoKit
        // nor the Security framework will do for us: SecKeyCreateRandomKey
        // makes the key and SecItemAdd stores it, but there is no public API
        // that puts a DER certificate around it. Confined to the transport, so
        // the protocol product stays dependency-free.
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
    ],
    targets: [
        .target(name: "RoomWireProtocol", path: "Sources/RoomWireProtocol"),
        .target(
            name: "RoomWireTransport",
            dependencies: [
                "RoomWireProtocol",
                .product(name: "X509", package: "swift-certificates"),
            ],
            path: "Sources/RoomWireTransport"
        ),
        // The lab tool: a real host and a real viewer, driven from a terminal,
        // plus the selftest that check.sh runs. macOS-only code lives here and
        // nowhere else.
        .executableTarget(name: "RoomWireLab", dependencies: ["RoomWireTransport"], path: "Sources/RoomWireLab"),
    ],
    swiftLanguageVersions: [.v5]
)
