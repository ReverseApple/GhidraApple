package lol.fairplay.ghidraapple.decompiler

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program

class GADecompiler(program: Program) {

    private var decompiler = DecompInterface().let { decompiler ->
        decompiler.openProgram(program)
        decompiler
    }

    fun decompile(function: Function) {
        TODO()
    }

}
