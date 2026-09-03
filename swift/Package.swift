// swift-tools-version:5.9
import PackageDescription

// RoomLink: the wire format and the decisions made about it, with no platform
// inside. One product today; `RoomLinkTransport` joins it once discovery,
// pairing and the two lanes are proven Mac-to-Mac.
//
// Swift 5 language mode on purpose: the consuming app builds in it, and these
// are plain value types whose only clock is a `TimeInterval` the caller passes
// in — there is nothing here for strict concurrency to protect.
let package = Package(
    name: "RoomLink",
    platforms: [.macOS("15.0"), .iOS("18.0")],
    products: [
        .library(name: "RoomLinkProtocol", targets: ["RoomLinkProtocol"]),
    ],
    targets: [
        .target(name: "RoomLinkProtocol", path: "Sources/RoomLinkProtocol"),
    ],
    swiftLanguageVersions: [.v5]
)
