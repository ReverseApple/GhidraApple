package lol.fairplay.ghidraapple.actions.te

import docking.ActionContext
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.context.ProgramLocationContextAction
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.listing.Function
import lol.fairplay.ghidraapple.GhidraApplePluginPackage

class RetypeFunctionAction(
    owner: String,
    val tool: PluginTool,
) : ProgramLocationContextAction(
        "Re-type Function",
        owner,
    ) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    companion object {
        private fun getMatchingFunctionForContext(context: ProgramLocationActionContext): Function? =
            if (context.hasFunctions()) {
                context.functions.first()
            } else {
                context.program.listing.getFunctionAt(context.address)
            }
    }

    override fun actionPerformed(context: ProgramLocationActionContext) {
        val matchingFunction = getMatchingFunctionForContext(context)
        if (matchingFunction == null) return
        tool.showDialog(
            ChooseDataTypeManagerDialog(
                tool,
                context.program,
                matchingFunction,
                { _, matchingFunctionDefinition ->
                    if (matchingFunctionDefinition === null) return@ChooseDataTypeManagerDialog
                    retypeFunction(matchingFunction, matchingFunctionDefinition, context.program)
                },
            ),
        )
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean {
        val typedContext =
            context as? ProgramLocationActionContext ?: return false
        return getMatchingFunctionForContext(typedContext) != null
    }
}
