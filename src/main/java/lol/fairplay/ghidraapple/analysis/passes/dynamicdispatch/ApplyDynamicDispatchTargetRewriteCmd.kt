package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.framework.cmd.Command
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import lol.fairplay.ghidraapple.core.objc.modelling.OCMethod

class ApplyDynamicDispatchTargetRewriteCmd(
    val callsite: Address,
    val targetFunction: Function,
    val sourceType: SourceType,
    val isApproximated: Boolean = false,
) : Command<Program> {
    init {
        if (targetFunction.isExternal) {
            throw IllegalArgumentException("Cannot rewrite to an external function")
        }
    }

    companion object {
        /**
         * For rewriting a dynamic dispatch call to an implementation that is part of the same [Program]
         */
        fun toMethod(
            program: Program,
            ocMethod: OCMethod,
            from: Address,
            sourceType: SourceType,
            isApproximated: Boolean = false,
        ): ApplyDynamicDispatchTargetRewriteCmd {
            val implAddress = program.addressFactory.defaultAddressSpace.getAddress(ocMethod.implAddress!!)
            val targetFunction = program.getFunctionManager().getFunctionAt(implAddress)
            return ApplyDynamicDispatchTargetRewriteCmd(from, targetFunction, sourceType, isApproximated)
        }

//        /**
//         * For rewriting a dynamic dispatch call to an implementation that is part of an external library
//         * which was created via [CreateObjCMethodThunkCmd]
//         */
//        fun toExternalThunk(cls: ObjectiveCClass, methodName: Selector): ApplyDynamicDispatchTargetRewriteCmd {
//            CreateObjCMethodThunkCmd(cls, methodName)
//        }
    }

    private var errorMsg: String? = null

    override fun applyTo(program: Program): Boolean {
        val refType = if (isApproximated) RefType.UNCONDITIONAL_CALL else RefType.CALL_OVERRIDE_UNCONDITIONAL

        val ref =
            program.referenceManager.addMemoryReference(
                callsite,
                targetFunction.entryPoint,
                refType,
                sourceType,
                0,
            )
        program.referenceManager.setPrimary(ref, true)
        return true
    }

    override fun getStatusMsg(): String? = errorMsg

    override fun getName(): String = "Apply Dynamic Dispatch Target Rewrite"
}
