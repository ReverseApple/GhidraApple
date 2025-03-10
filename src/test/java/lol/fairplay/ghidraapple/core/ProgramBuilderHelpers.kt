package lol.fairplay.ghidraapple.core

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.listing.Function

fun ProgramBuilder.createFunction(
    addr: String,
    bytes: ByteArray,
): Function {
    setBytes(addr, bytes)
    val func = createFunction(addr)
    disassemble(addr, bytes.size)
    return func
}
