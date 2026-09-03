// Pure Kotlin/JVM. No Android Gradle Plugin, no SDK, no device — a JDK runs
// these tests in a second, which is the whole reason the wire format lives here
// and not beside the code that needs a phone.
plugins {
    kotlin("jvm")
}

repositories { mavenCentral() }

kotlin { jvmToolchain(17) }

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    // The contract belongs to the protocol, not to this implementation of it,
    // so it sits at the repository root. rootDir is kotlin/.
    val contract = rootDir.parentFile.resolve("protocol")
    systemProperty("vectors", contract.resolve("vectors.txt").absolutePath)
    systemProperty("transcripts", contract.resolve("transcripts.txt").absolutePath)
    // Declared as inputs, and not merely handed over as properties. Without
    // this Gradle sees nothing it depends on change when only the contract
    // moves, reports the task UP-TO-DATE, and the suite goes green having never
    // read the new format. That is the precise drift this module exists to
    // catch, so it does not get to hide in the build cache.
    inputs.files(fileTree(contract) { include("*.txt") }).withPropertyName("contract")
    testLogging { showStandardStreams = true }
}
