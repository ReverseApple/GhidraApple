package org.reverseapple.utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MachOHeader {

    static final int MAGIC = 0xFEEDFACF;

    public final int version;
    public final int cputype;
    public final int cpusubtype;
    public final int filetype;
    public final int ncmds;
    public final int sizeofcmds;
    public final int flags;
    public final int reserved;

    public MachOHeader(Program program) throws MemoryAccessException {
        Memory memory = program.getMemory();
        MemoryBlock text = memory.getBlock("__TEXT");

        if (text == null) {
            throw new IllegalArgumentException("Block '__TEXT' not found in memory");
        }

        Address start = text.getStart();

        byte[] headerBytes = new byte[32];
        text.getBytes(start, headerBytes);

        ByteBuffer buf = ByteBuffer.wrap(headerBytes);
        buf.order(ByteOrder.LITTLE_ENDIAN);

        this.version = buf.getInt();
        this.cputype = buf.getInt();
        this.cpusubtype = buf.getInt();
        this.filetype = buf.getInt();
        this.ncmds = buf.getInt();
        this.sizeofcmds = buf.getInt();
        this.flags = buf.getInt();
        this.reserved = buf.getInt();
    }

}
