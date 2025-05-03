package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.context.ProgramLocationContextAction
import ghidra.app.decompiler.ClangStatement
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.framework.plugintool.PluginTool
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.doesPCodeOpPutStackBlockPointerOnStack
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.doesReferenceStackBlockSymbol
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.isBlockLayout

class MarkAsStackBlockAction(
    owner: String,
    val plugin: PluginTool,
) : ProgramLocationContextAction(
        "Mark As Objective-C Stack Block",
        owner,
    ) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(context: ProgramLocationActionContext) {
        plugin.executeBackgroundCommand(MarkNSConcreteStackBlock(context.program, context.address), context.program)
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean {
        val typedContext =
            context as? ProgramLocationActionContext ?: return false

        // If this is already a block layout, don't allow it to be marked again.
        if (typedContext.location.isBlockLayout) return false

        if (typedContext is DecompilerActionContext) {
            val parent = typedContext.tokenAtCursor.Parent()
            if (parent is ClangStatement) {
                val op = parent.pcodeOp
                return doesPCodeOpPutStackBlockPointerOnStack(op, typedContext.program)
            }
            return false
        }

        return typedContext.program.listing
            .getInstructionAt(typedContext.address)
            ?.doesReferenceStackBlockSymbol ?: return false
    }
}
