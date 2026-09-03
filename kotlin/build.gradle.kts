// Nothing is applied at the root: :protocol is plain Kotlin/JVM and :transport,
// when it arrives, is Android. Declaring the version here keeps them in step.
plugins {
    kotlin("jvm") version "2.2.20" apply false
}

allprojects {
    group = "com.roomlink"
    version = "0.1.0"
}
