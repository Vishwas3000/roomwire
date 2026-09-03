// The Kotlin implementation of RoomWire.
//
//   :protocol   pure Kotlin/JVM. No Android SDK, no emulator, no device. The
//               wire format and the four decisions made about it — ChainGate,
//               Pacer, CursorMotion, Pointer — each a twin of a Swift file in
//               ../swift/Sources/RoomWireProtocol. Held to the Swift side by
//               protocol/vectors.txt (bytes) and protocol/transcripts.txt
//               (behaviour), both generated from Swift and replayed here, so a
//               difference between the two is a failing test and not a corrupt
//               frame on somebody's phone months later.
//
//   :transport  discovery, pairing and the two lanes. Needs the Android SDK,
//               which is why it is a separate module, why :protocol never
//               depends on it, and why it is included only when there is an SDK
//               to include it with. Its FakeViewer needs none of that: it is
//               plain Kotlin behind the same interface, so a consuming app can
//               build its whole viewer against it with no device in the room.
//
// That dependency arrow is the design. Everything that can be decided without
// a network or a screen is decided in :protocol, where a laptop runs the tests
// in a second.
//
// The plugin repositories are declared here and not only in the app that
// consumes this: an included build brings its own pluginManagement, and
// google() is where the Android Gradle Plugin lives.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "roomwire"

include(":protocol")

// :transport needs the Android SDK to configure at all, so a machine without
// one still runs ./check.sh — it just runs the half that does not need a phone.
if (System.getenv("ANDROID_HOME") != null || file("local.properties").exists()) {
    include(":transport")
}
