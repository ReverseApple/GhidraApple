package lol.fairplay.ghidraapple.core.objc.modelling

class Dyld {
    enum class Platform(
        val value: UInt,
        val prettyName: String? = null,
    ) {
        UNKNOWN(0u),
        MACOS(1u, "macOS"),
        IOS(2u, "iOS"),
        TVOS(3u, "tvOS"),
        WATCHOS(4u, "watchOS"),
        BRIDGEOS(5u, "bridgeOS"),
        MACCATALYST(6u, "Mac Catalyst"),
        IOSSIMULATOR(7u, "iOS (Simulator)"),
        TVOSSIMULATOR(8u, "tvOS (Simulator)"),
        WATCHOSSIMULATOR(9u, "watchOS (Simulator)"),
        DRIVERKIT(10u),
        VISIONOS(11u, "visionOS"),
        VISIONOSSIMULATOR(12u, "visionOS (Simulator)"),
        ;

        companion object {
            fun getPlatform(value: UInt): Platform? = entries.firstOrNull { it.value == value }
        }
    }

    data class Version(
        private val version: UInt,
    ) {
        val major = (version shr 16) and 0xffffu
        val minor = (version shr 8) and 0xffu
        val patch = version and 0xffu

        override fun toString(): String {
            var minorAppended = false
            var version = "$major"
            if ((minor != 0u && patch == 0u) || (minor == 0u && patch != 0u)) {
                version += ".$minor"
                minorAppended = true
            }
            if (patch != 0u && minorAppended) version += ".$patch"
            return version
        }
    }
}
