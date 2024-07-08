package lol.fairplay.ghidraapple.analysis.langannotation.objc

import ghidra.app.script.GhidraScript
import ghidra.program.model.listing.Function

class OCAnnotateScript: GhidraScript() {

    val program = currentProgram;

    override fun run() {
        val function = getFunctionAt(currentAddress)

        analyzeFunction(function)
    }

    private fun analyzeFunction(function: Function) {
        val instructions = program.listing.getInstructions(function.body, true)

        instructions.forEach { instr ->

        }
    }

}
