package org.reverseapple.ghidraapple.analyzers.selectoralias;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import org.reverseapple.ghidraapple.utils.MachOCpuID;

public class AliasOpcodeSignature {

    static final String[] AARCH64 = new String[] {
            "adrp",
            "ldr",
            "adrp",
            "ldr",
            "br"
    };

    static final String[] AARCH64E = new String[] {
            "adrp",
            "ldr",
            "adrp",
            "add",
            "ldr"
    };

    public static String[] getInstructionSignature(MachOCpuID cpu) {

        if (cpu == MachOCpuID.AARCH64) {
            return AARCH64;
        } else if (cpu == MachOCpuID.AARCH64E) {
            return AARCH64E;
        } else {
            throw new IllegalArgumentException("Unsupported CPU: " + cpu);
        }
    }

}
