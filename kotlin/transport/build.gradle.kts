// The Android half: discovery, pairing and the two lanes, plus the FakeViewer
// that lets a consuming app build its viewer with no Mac and no phone.
//
// No kotlin("android") here — the Android Gradle Plugin 9 has Kotlin built in,
// and applying both is an error.
plugins {
    id("com.android.library")
}

android {
    namespace = "com.roomwire.transport"
    compileSdk = 36

    defaultConfig {
        // NsdManager.registerServiceInfoCallback is API 34, but the app that
        // consumes this already sets its own floor higher than that.
        minSdk = 30
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // api, not implementation: everything this exposes — Packet, ChunkHeader,
    // the state machines — is the consumer's to use too.
    api(project(":protocol"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")

    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // FakeViewer schedules everything with delay on a scope the caller supplies,
    // so runTest's virtual clock drives it and a 1.5-second approval costs no
    // real time.
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}

tasks.withType<Test> { useJUnitPlatform() }
