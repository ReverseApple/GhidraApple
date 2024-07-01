package org.reverseapple.ghidraapple.utils;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public enum MachOCpuID {
    x86,
    x86_64,
    AARCH64,
    AARCH64E,
    POWERPC,
    UNKNOWN;

    public static MachOCpuID getCPU(Program program) throws MemoryAccessException {
        Language lang = program.getLanguage();

        String processor = lang.getProcessor().toString();

        if (processor.equals("AARCH64")) {

            // Read the CPU subtype from the MachO header...
            MachOHeader header = new MachOHeader(program);

            if (header.cpusubtype == 0x80000002) {
                return AARCH64E;
            }

            return AARCH64;
        }

        String bitness = lang.getLanguageID().toString().split(":")[2];

        switch (processor) {
            case "PowerPC" -> {
                return POWERPC;
            }
            case "x86" -> {
                if (bitness.equals("64")) {
                    return x86_64;
                } else {
                    return x86;
                }
            }
        }

        return UNKNOWN;
    }

}
