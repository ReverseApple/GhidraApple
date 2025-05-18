package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.context.ProgramLocationContextAction
import ghidra.app.decompiler.ClangVariableToken
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.framework.plugintool.PluginTool
import lol.fairplay.ghidraapple.GhidraApplePluginPackage

class MarkAsBlockByRefAction(
    owner: String,
    val plugin: PluginTool,
) : ProgramLocationContextAction(
        "Mark As Objective-C Block Reference Variable",
        owner,
    ) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(context: ProgramLocationActionContext) {
        plugin.executeBackgroundCommand(MarkBlockByRef(context.program, context.address), context.program)
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean {
        val typedContext =
            context as? DecompilerActionContext ?: return false

        return typedContext.tokenAtCursor is ClangVariableToken // TODO: Make this check more robust.
    }
}
