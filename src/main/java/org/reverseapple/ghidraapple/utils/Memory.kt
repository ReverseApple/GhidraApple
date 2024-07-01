package org.reverseapple.ghidraapple.utils

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException

class Memory {
    companion object {

        fun readMemString(program: Program, address: Address): String? {
            // read a null-terminated string from memory.
            val memory = program.memory
            val builder = StringBuilder()

            var currentAddress = address
            try {
                var b: Byte;
                while (true) {
                    b = memory.getByte(currentAddress)
                    if (b.toInt() == 0) break
                    builder.append(b.toInt().toChar())
                    currentAddress = currentAddress.add(1)
                }
            } catch (e: MemoryAccessException) {
                return null
            }
            return builder.toString()
        }

    }
}
