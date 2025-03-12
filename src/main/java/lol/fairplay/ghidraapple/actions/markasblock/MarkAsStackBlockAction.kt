package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.context.ProgramLocationContextAction
import ghidra.app.decompiler.DecompilerLocation
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.symbol.RefType
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType

class MarkAsStackBlockAction(owner: String, val plugin: PluginTool) : ProgramLocationContextAction(
    "Mark As Objective-C Global Block",
    owner,
) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(context: ProgramLocationActionContext) {
        plugin.executeBackgroundCommand(ApplyNSConcreteStackBlock(context.program, context.address), context.program)
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean {
        val typedContext =
            context as? ProgramLocationActionContext ?: return false
        if (BlockLayoutDataType.isLocationBlockLayout(typedContext.location)) return false

        val location = typedContext.location

        // This is a quick-and-dirty check for cases the latter tests wouldn't catch.
        when (location) {
            is DecompilerLocation -> {
                location.token.lineParent?.let {
                    // Tokens: [variableName], [space], [equals], [space], ["PTR___NSConcreteStackBlock*"], ...
                    if (it.getToken(4).toString().startsWith("PTR___NSConcreteStackBlock")) return true
                }
            }
        }

        // We check if this is an instruction and look for the start of the building of a stack block.
        typedContext.program.listing.getInstructionAt(typedContext.address)?.let {
            typedContext.program.symbolTable
                .getSymbols(
                    it.referencesFrom
                        .firstOrNull { it.referenceType == RefType.DATA }
                        ?.toAddress
                        ?: return false,
                ).firstOrNull { it.isPrimary }
                ?.apply { if (name != "__NSConcreteStackBlock" && name != "__NSStackBlock__") return false }
                ?: return false
            return true
        }

        return false
    }
}
