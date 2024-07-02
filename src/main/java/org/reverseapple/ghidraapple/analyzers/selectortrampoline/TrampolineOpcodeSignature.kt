package org.reverseapple.ghidraapple.analyzers.selectortrampoline

import org.reverseapple.ghidraapple.utils.MachOCpuID

class TrampolineOpcodeSignature {

    companion object {
        private val AARCH64 = arrayOf(
            "adrp",
            "ldr",
            "adrp",
            "ldr",
            "br"
        )

        private val AARCH64E = arrayOf(
            "adrp",
            "ldr",
            "adrp",
            "add",
            "ldr",
            "braa"
        )

        fun getInstructionSignature(cpu: MachOCpuID): Array<String> {
            return when (cpu) {
                MachOCpuID.AARCH64 -> AARCH64
                MachOCpuID.AARCH64E -> AARCH64E
                else -> throw IllegalArgumentException("Unsupported CPU: $cpu")
            }
        }
    }
}
