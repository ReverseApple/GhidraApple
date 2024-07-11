package lol.fairplay.ghidraapple.core.decompiler

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileResults
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program


class DecompiledFunctionProvider(program: Program) {

    private val ifc: DecompInterface = DecompInterface()

    init {
        ifc.openProgram(program)
    }

    fun getDecompiled(function: Function, timeout: Int = 5): DecompileResults {
        return ifc.decompileFunction(function, timeout, null)
    }

}

