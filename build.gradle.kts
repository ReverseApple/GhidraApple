import java.util.Properties

// This cannot be used inside the `plugins` block, but can (and is) used elsewhere and
//  should match the version used inside the `plugins` block.
val kotlinVersion = "1.9.23"

plugins {
    kotlin("jvm") version "1.9.23"
    kotlin("plugin.serialization") version "1.9.23"
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
val ghidraInstallDir: String? =
    System.getenv("GHIDRA_INSTALL_DIR") ?: project.findProperty("GHIDRA_INSTALL_DIR") as String?

data class Version(
    val major: Int,
    val minor: Int,
    val patch: Int = 0,
) : Comparable<Version> {
    override fun compareTo(other: Version): Int =
        when {
            major != other.major -> major.compareTo(other.major)
            minor != other.minor -> minor.compareTo(other.minor)
            else -> patch.compareTo(other.patch)
        }

    companion object {
        fun parse(version: String): Version {
            val parts = version.split(".")
            return Version(
                major = parts[0].toInt(),
                minor = parts.getOrNull(1)?.toInt() ?: 0,
                patch = parts.getOrNull(2)?.toInt() ?: 0,
            )
        }
    }
}

if (ghidraInstallDir != null) {
    val ghidraPropsFile = file("$ghidraInstallDir/Ghidra/application.properties")
    if (!ghidraPropsFile.exists()) {
        throw GradleException("Unable to find the Ghidra properties file")
    }
    val ghidraProps =
        ghidraPropsFile.inputStream().use { stream ->
            Properties().apply { load(stream) }
        }
    val (ghidraAppName, ghidraAppVersion, ghidraReleaseName) =
        run {
            val appName =
                ghidraProps.getProperty("application.name")
                    ?: throw GradleException("Unable to get Ghidra app name")
            val appVersion =
                ghidraProps.getProperty("application.version")
                    ?: throw GradleException("Unable to get Ghidra app version")
            val releaseName =
                ghidraProps.getProperty("application.release.name")
                    ?: throw GradleException("Unable to Ghidra release name")
            Triple(appName, appVersion, releaseName)
        }
    if (ghidraAppName != "Ghidra") {
        throw GradleException("GHIDRA_INSTALL_DIR does not point to a valid Ghidra installation")
    }
    if (ghidraReleaseName != "PUBLIC") {
        logger.warn("Building against a non-PUBLIC version of Ghidra. Release name is $ghidraReleaseName.")
    }
    // TODO: Handle different source sets based on Ghidra version.

    apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")
} else {
    throw GradleException("GHIDRA_INSTALL_DIR is not defined!")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib", kotlinVersion))
    testImplementation(kotlin("test", kotlinVersion))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.3")
    testImplementation("org.json:json:20240303")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.3")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:5.10.3")
    // This isn't the latest version, but it is the latest version that supports Kotlin <2.0.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    runtimeOnly(
        fileTree(
            mapOf(
                "dir" to "$ghidraInstallDir/Ghidra/Extensions",
                "include" to listOf("**/*.jar"),
            ),
        ),
    )
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
    maxParallelForks = Runtime.getRuntime().availableProcessors().div(2)
}

sourceSets {
    main {
        kotlin {
            srcDirs("ghidra_scripts")
        }
    }
}

idea {
    module {
        isDownloadJavadoc = true
        isDownloadSources = true
    }
}

// ----------------------END "DO NOT MODIFY" SECTION-------------------------------
