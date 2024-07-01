package org.reverseapple.ghidraapple.analyzers.selectortrampoline


import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.InstructionIterator
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.Symbol

import org.reverseapple.ghidraapple.utils.MachOCpuID
import org.reverseapple.ghidraapple.utils.Memory

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
            MachOCpuID.AARCH64 -> {
                if (instructions[1].mnemonicString != "ldr")
                    return null

                // second parameter of second instruction.
                val refs = instructions[1].getOperandReferences(0)

                if (refs.size != 1)
                    return null

                return function.program.listing.getDefinedDataAt(refs[0].toAddress).value.toString()
            }
            MachOCpuID.AARCH64E -> {
                TODO()
            }
            else -> null
        }

    }

    fun resolveClasses(): Array<String> {
        TODO()
    }
}
