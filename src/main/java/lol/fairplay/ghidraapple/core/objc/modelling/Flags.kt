package lol.fairplay.ghidraapple.core.objc.modelling

enum class ClassFlags(val bit: ULong) {
    IS_SWIFT(1uL shl 0);

    companion object {
        fun fromValue(flags: ULong): Set<ClassFlags> {
            return entries.filter { (flags and it.bit) != 0uL }.toSet()
        }
    }
}
