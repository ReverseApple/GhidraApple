package lol.fairplay.ghidraapple.actions.te

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.listing.Function
import lol.fairplay.ghidraapple.GhidraApplePluginPackage

class RetypeFunctionsAction(
    owner: String,
    val tool: PluginTool,
) : DockingAction(
        "Re-type Functions",
        owner,
    ) {
    init {
        menuBarData = MenuData(arrayOf(GhidraApplePluginPackage.PKG_NAME, this.name))
    }

    companion object {
        private fun getMatchingFunctionForContext(context: ProgramLocationActionContext): Function? =
            if (context.hasFunctions()) {
                context.functions.first()
            } else {
                context.program.listing.getFunctionAt(context.address)
            }
    }

    override fun actionPerformed(context: ActionContext) {
        val typedContext = context as? ProgramLocationActionContext ?: return
        val matchingFunction = getMatchingFunctionForContext(typedContext)
        if (matchingFunction == null) return
        tool.showDialog(
            ChooseDataTypeManagerDialog(
                tool,
                typedContext.program,
                matchingFunction,
            ) { _, matchingFunctionDefinition ->
                if (matchingFunctionDefinition === null) return@ChooseDataTypeManagerDialog
                retypeFunction(matchingFunction, matchingFunctionDefinition, context.program)
            },
        )
    }

    override fun isEnabled(): Boolean = true
}
