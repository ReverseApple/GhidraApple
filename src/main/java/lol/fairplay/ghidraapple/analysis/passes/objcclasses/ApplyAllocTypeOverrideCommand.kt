package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.framework.cmd.Command
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.symbol.Symbol

class ApplyAllocTypeOverrideCommand(val callsite: Address, val type: DataType, val withVarargs: Boolean = true) : Command<Program> {
    var errorMsg: String? = null

    override fun applyTo(program: Program): Boolean {
        // Check for existing override
        val primarySymbol: Symbol? = program.symbolTable.getSymbols(callsite).singleOrNull { it.isPrimary }
        val existingOverride = primarySymbol?.let { HighFunctionDBUtil.readOverride(it) }
        if (existingOverride != null) {
            errorMsg = "Override already exists for $callsite"
            return false
        }

        val signature = generateFunctionSignatureForType(type, withVarargs)
        val function = program.functionManager.getFunctionContaining(callsite)
        HighFunctionDBUtil.writeOverride(function, callsite, signature)
        return true
    }

    override fun getStatusMsg(): String? = errorMsg

    override fun getName(): String {
        return "Apply Alloc Type Override"
    }

    private fun generateFunctionSignatureForType(
        type: DataType,
        withVarargs: Boolean,
    ): FunctionSignature {
        val fsig = FunctionDefinitionDataType("tmpname")
        fsig.returnType = type
        fsig.arguments = arrayOf(ParameterDefinitionImpl("cls", type, null))
        if (withVarargs) {
            fsig.setVarArgs(true)
        }
        return fsig
    }
}
