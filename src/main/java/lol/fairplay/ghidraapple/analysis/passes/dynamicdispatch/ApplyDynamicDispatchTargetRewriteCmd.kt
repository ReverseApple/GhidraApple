package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.framework.cmd.Command
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import lol.fairplay.ghidraapple.analysis.utilities.setCallTarget
import lol.fairplay.ghidraapple.core.objc.modelling.OCMethod

class ApplyDynamicDispatchTargetRewriteCmd(
    val callsite: Address,
    val target: OCMethod,
    val sourceType: SourceType,
    val isApproximated: Boolean = false,
): Command<Program> {
    private var errorMsg: String? = null

    override fun applyTo(program: Program): Boolean {
        if (target.implAddress == null) {
            errorMsg = "Target method has no implementation address"
            return false
        }
        val targetAddress = program.addressFactory.defaultAddressSpace.getAddress(target.implAddress)
        val targetFunction = program.functionManager.getFunctionAt(targetAddress) ?: run {
            errorMsg = "Target method implementation address is not a function"
            return false
        }
        val refType = if (isApproximated) RefType.UNCONDITIONAL_CALL else RefType.CALL_OVERRIDE_UNCONDITIONAL
        val ref = program.referenceManager.addMemoryReference(
            callsite, targetFunction.entryPoint, refType, sourceType, 0
        )
        program.referenceManager.setPrimary(ref, true)
        return true
    }

    override fun getStatusMsg(): String? {
        return errorMsg
    }

    override fun getName(): String {
        return "Apply Dynamic Dispatch Target Rewrite"
    }
}
