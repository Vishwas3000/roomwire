// The Kotlin implementation of RoomLink.
//
//   :protocol   pure Kotlin/JVM. No Android SDK, no emulator, no device. The
//               wire format and the four decisions made about it — ChainGate,
//               Pacer, CursorMotion, Pointer — each a twin of a Swift file in
//               ../swift/Sources/RoomLinkProtocol. Held to the Swift side by
//               protocol/vectors.txt (bytes) and protocol/transcripts.txt
//               (behaviour), both generated from Swift and replayed here, so a
//               difference between the two is a failing test and not a corrupt
//               frame on somebody's phone months later.
//
//   :transport  arrives next: discovery, pairing and the two lanes. Needs the
//               Android SDK, which is why it is a separate module and why
//               :protocol never depends on it.
//
// That dependency arrow is the design. Everything that can be decided without
// a network or a screen is decided in :protocol, where a laptop runs the tests
// in a second.
rootProject.name = "roomlink"

include(":protocol")
