package lol.fairplay.ghidraapple.decompiler.core

import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeBlock
import ghidra.program.model.pcode.PcodeBlockBasic

class Context(
    val highFunction: HighFunction,
) {
    var currentBasicBlock: PcodeBlock? = null

    val program: Program
        get() = highFunction.function.program

}
