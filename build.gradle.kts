plugins {
    kotlin("jvm") version "2.1.10"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.2"
    id("idea")
}

// Builds a Ghidra Extension for a given Ghidra installation.
//
// An absolute path to the Ghidra installation directory must be supplied either by setting the
// GHIDRA_INSTALL_DIR environment variable or Gradle project property:
//
//     > export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>
//     > gradle
//
//         or
//
//     > gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>
//
// Gradle should be invoked from the directory of the project to build.  Please see the
// application.gradle.version property in <GHIDRA_INSTALL_DIR>/Ghidra/application.properties
// for the correction version of Gradle to use for the Ghidra installation you specify.

// ----------------------START "DO NOT MODIFY" SECTION------------------------------
val ghidraInstallDir: String? = System.getenv("GHIDRA_INSTALL_DIR") ?: project.findProperty("GHIDRA_INSTALL_DIR") as String?

if (ghidraInstallDir != null) {
    apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")
} else {
    throw GradleException("GHIDRA_INSTALL_DIR is not defined!")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.3")
    testImplementation("org.json:json:20240303")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.3")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:5.10.3")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}

sourceSets {
    main {
        kotlin {
            srcDirs("ghidra_scripts")
        }
    }
}
// ----------------------END "DO NOT MODIFY" SECTION-------------------------------
