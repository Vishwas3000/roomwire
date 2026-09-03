// Nothing is applied at the root: :protocol is plain Kotlin/JVM and :transport
// is Android. Declaring the versions here keeps them in step.
//
// The AGP version is load-bearing beyond this build. An app that includes this
// one as a composite build shares one plugin classpath with it, and two
// versions of the Android Gradle Plugin on that classpath fail to load — so
// this number and the consuming app's have to be the same number.
plugins {
    kotlin("jvm") version "2.2.20" apply false
    id("com.android.library") version "9.3.0" apply false
}

allprojects {
    group = "com.roomwire"
    version = "0.1.0"
}
