package lol.fairplay.ghidraapple.actions.setasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout

class SetAsBlockAction : DockingAction("Set As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(actionContext: ActionContext?) {
        val programLocationContext =
            actionContext as? ProgramLocationActionContext ?: return
        BlockLayout(programLocationContext.program, programLocationContext.address)
            .apply {
                // TODO: Determine if we can get this to be undone with a single undo command instead of several.
                programLocationContext.program.withTransaction<Exception>("update program") { updateProgram() }
            }
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean = context is ProgramLocationActionContext
}
