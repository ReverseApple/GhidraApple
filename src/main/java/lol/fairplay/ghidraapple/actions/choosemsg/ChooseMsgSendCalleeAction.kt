package lol.fairplay.ghidraapple.actions.choosemsg

import docking.action.MenuData
import ghidra.app.decompiler.ClangFuncNameToken
import ghidra.app.decompiler.DecompilerLocation
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction
import ghidra.program.model.pcode.PcodeOp
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.utilities.getFunctionForPCodeCall

class ChooseMsgSendCalleeAction : AbstractDecompilerAction("Choose msgSend Callee") {
    init {
        description = ""
        popupMenuData = MenuData(arrayOf("Choose Dynamic Dispatch Callee"), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun isEnabledForDecompilerContext(ctx: DecompilerActionContext): Boolean {
        val location = ctx.location as DecompilerLocation
        if (location.token !is ClangFuncNameToken) {
            return false
        }
        val pCodeOp: PcodeOp? = getPcodeOp(ctx)
        val optFunc = getFunctionForPCodeCall(ctx.program, pCodeOp)
        if (optFunc.isEmpty) {
            return false
        }
        val func = optFunc.get()
        if (func.name == "_objc_msgSend") {
            return true
        }
        // Check if the function is a trampoline by checking if it is in the trampoline section `__objc_stubs`
        if (func.program.memory.getBlock(func.entryPoint).name == "__objc_stubs") {
            return true
        }
        return false
    }

    private fun getPcodeOp(ctx: DecompilerActionContext): PcodeOp? {
        val location = ctx.location as DecompilerLocation
        val pCodeOp = location.token.pcodeOp
        return pCodeOp
    }

    override fun decompilerActionPerformed(ctx: DecompilerActionContext) {
        // Get the selector name that is called here
        // This can either be the selector argument in x1, or the name of the stub function
        // For now we only support the renamed stub

        val pCodeOp = getPcodeOp(ctx)
        with(ctx) {
            val func = getFunctionForPCodeCall(program, pCodeOp).get()
            if (func.name == "_objc_msgSend") {
                // TODO: We can extract the selector here (if it is a constant) and use it to narrow down the search
                tool.showDialog(ChooseMsgSendCalleeDialog(tool, program, location.address, null))
            } else {
                tool.showDialog(ChooseMsgSendCalleeDialog(tool, program, location.address, func.name))
            }
        }
    }
}
