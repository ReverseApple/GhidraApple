package lol.fairplay.ghidraapple.core

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.data.TerminatedStringDataType
import ghidra.program.model.listing.Function

fun ProgramBuilder.createFunction(
    stringAddress: String,
    bytes: ByteArray,
    name: String? = null,
): Function {
    setBytes(stringAddress, bytes)
    val func = createEmptyFunction(name, stringAddress, bytes.size, DataType.DEFAULT)
    disassemble(stringAddress, bytes.size)
    return func
}

/**
 * Set a null-terminated string at the given address.
 *
 * Encodes it as ascii, appends null byte, stores the bytes and optionally applies the string data type to the location
 * Some code relies on data being already typed as a string, so this is useful, but in general this should not be needed
 * and so the default is to not do this
 */
fun ProgramBuilder.setNullTerminatedString(
    addr: String,
    string: String,
    applyStringType: Boolean = false,
) {
    val bytes = string.toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
    setBytes(addr, bytes)
    if (applyStringType) {
        applyStringDataType(addr, TerminatedStringDataType.dataType, 1)
    }
}

fun ProgramBuilder.createThunk(
    addr: String,
    thunkOf: Function,
) {
    this.tx<Exception> {
        val thunk =
            this.createEmptyFunction(
                thunkOf.name,
                addr,
                1,
                thunkOf.returnType,
            )
        thunk.setThunkedFunction(thunkOf)
    }
}
