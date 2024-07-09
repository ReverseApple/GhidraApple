package lol.fairplay.ghidraapple.core.common

import ghidra.program.model.lang.Language
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException

enum class MachOCpuID {
    x86,
    x86_64,
    AARCH64,
    AARCH64E,
    POWERPC;

    companion object {

        @JvmStatic
        @Throws(MemoryAccessException::class)
        fun getCPU(program: Program): MachOCpuID? {
            val lang: Language = program.language

            val processor: String = lang.processor.toString()

            if (processor == "AARCH64") {
                // Read the CPU subtype from the MachO header...
                val header = MachOHeader(program)

                return if (header.cpusubtype == 0x80000002.toInt()) {
                    AARCH64E
                } else {
                    AARCH64
                }
            }

            val bitness: String = lang.languageID.toString().split(":")[2]

            return when (processor) {
                "PowerPC" -> POWERPC
                "x86" -> if (bitness == "64") x86_64 else x86
                else -> null
            }
        }
    }
}
