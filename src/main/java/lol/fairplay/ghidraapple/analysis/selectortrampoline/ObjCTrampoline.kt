package lol.fairplay.ghidraapple.analysis.selectortrampoline


import ghidra.program.database.symbol.FunctionSymbol
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.InstructionIterator
import ghidra.program.model.symbol.SymbolType
import lol.fairplay.ghidraapple.core.common.MachOCpuID

class ObjCTrampoline(val function: Function, val cpuId: MachOCpuID) {

    private val program = function.program

    fun getSelectorString(): String? {

        val instrIter: InstructionIterator = function
            .program
            .listing
            .getInstructions(function.body, true)

        val instructions = instrIter.toList()

        return when (cpuId) {
            MachOCpuID.AARCH64,
            MachOCpuID.AARCH64E -> {
                if (instructions[1].mnemonicString != "ldr")
                    return null

                // second parameter of second instruction.
                val refs = instructions[1].getOperandReferences(0)

                if (refs.size != 1)
                    return null

                return program.listing.getDefinedDataAt(refs[0].toAddress).value.toString()
            }
            else -> null
        }

    }

    fun findActualImplementation(): FunctionSymbol? {
        val selectorString = getSelectorString() ?: return null

        val symbols = program.symbolTable.getSymbols(selectorString).filter { symbol->
            symbol.symbolType == SymbolType.FUNCTION && function.symbol != symbol
        }

        if (symbols.size == 1) {
            return symbols[0] as FunctionSymbol
        }

        return null
    }

    fun resolveClasses(): Array<String> {
        TODO()
    }
}
