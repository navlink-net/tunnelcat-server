plugins {
    kotlin("jvm") version "1.9.24"
    `java-library`
}

group = "com.tunnelcat"
version = "0.1.0"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17) // java.net.UnixDomainSocketAddress needs JDK 16+
}

dependencies {
    implementation("org.json:json:20240303")
    testImplementation(kotlin("test"))
}
