package org.reverseapple.ghidraapple.utils

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryBlock
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MachOHeader(program: Program) {

    val cputype: Int
    val cpusubtype: Int
    val filetype: Int
    val ncmds: Int
    val sizeofcmds: Int
    val flags: Int
    val reserved: Int

    init {
        val memory: Memory = program.memory

        val text: MemoryBlock = memory.getBlock("__TEXT")
            ?: throw IllegalArgumentException("Block '__TEXT' not found in memory")

        val start: Address = text.start

        val headerBytes = ByteArray(32)
        text.getBytes(start, headerBytes)

        val buf: ByteBuffer = ByteBuffer.wrap(headerBytes).apply {
            order(ByteOrder.LITTLE_ENDIAN)

            // Skip the magic.
            position(4)
        }

        cputype = buf.int
        cpusubtype = buf.int
        filetype = buf.int
        ncmds = buf.int
        sizeofcmds = buf.int
        flags = buf.int
        reserved = buf.int
    }

    companion object {
        const val MAGIC = 0xFEEDFACF
    }
}
