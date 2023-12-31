package org.reverseapple.analyzers.selectoralias;

import ghidra.framework.Architecture;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import org.reverseapple.utils.MachOCpuID;

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

    public static String[] getInstructionSignature(Program program) throws MemoryAccessException {
        MachOCpuID cpu = MachOCpuID.getCPU(program);

        if (cpu == MachOCpuID.AARCH64) {
            return AARCH64;
        } else if (cpu == MachOCpuID.AARCH64E) {
            return AARCH64E;
        } else {
            throw new IllegalArgumentException("Unsupported CPU: " + cpu);
        }
    }

}
