package lol.fairplay.ghidraapple.analysis.langannotation

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class FnCall(program: Program, address: Address) {

    private var function: Function
    private val dec = DecompiledFunctionProvider(program)

    init {
        val callOp = program.listing.getInstructionAt(address).pcode.find {
            it.opcode == PcodeOp.CALL
        } ?: throw Exception("FnCall tried resolving a non-call.")

        // Resolve the function that's being called...
        this.function = program.functionManager.getFunctionAt(callOp.inputs[0].address) ?: throw Exception("Could not resolve callee.")
    }

    fun analyze() {
        val decompiled = dec.getDecompiled(function)

        val nodes = decompiled.cCodeMarkup.stream()

    }


    private fun mapCallToClangNode() {

    }

}
