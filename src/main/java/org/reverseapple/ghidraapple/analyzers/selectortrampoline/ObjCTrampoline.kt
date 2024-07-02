package org.reverseapple.ghidraapple.analyzers.selectortrampoline


import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.InstructionIterator
import org.reverseapple.ghidraapple.utils.MachOCpuID

class ObjCTrampoline(val function: Function, val cpuId: MachOCpuID) {

    fun getSelectorString(): String? {

        val instrIter: InstructionIterator = function
            .program
            .listing
            .getInstructions(function.body, true)

        val instructions = mutableListOf<Instruction>()
        while (instrIter.hasNext()) {
            instructions.add(instrIter.next())
        }

        return when (cpuId) {
            MachOCpuID.AARCH64,
            MachOCpuID.AARCH64E -> {
                if (instructions[1].mnemonicString != "ldr")
                    return null

                // second parameter of second instruction.
                val refs = instructions[1].getOperandReferences(0)

                if (refs.size != 1)
                    return null

                return function.program.listing.getDefinedDataAt(refs[0].toAddress).value.toString()
            }
            else -> null
        }

    }

    fun resolveClasses(): Array<String> {
        TODO()
    }
}
