package lol.fairplay.ghidraapple.actions.setasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.program.model.data.PointerDataType
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout

class SetAsBlockAction : DockingAction("Set As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(actionContext: ActionContext?) {
        val programLocationContext =
            actionContext as? ProgramLocationActionContext ?: return
        val dataAtLocation =
            programLocationContext.program.listing.getDataAt(programLocationContext.address)
                ?: throw IllegalArgumentException(
                    "No data at address 0x${programLocationContext.address}. Please operate only on data. " +
                        // TODO: Support stack blocks.
                        "Stack blocks are not yet supported.",
                )
        if (dataAtLocation.dataType != PointerDataType.dataType) {
            throw IllegalArgumentException(
                "The address 0x${programLocationContext.address} does not contain a pointer. " +
                    "This is probably not a block. Please start with an address that contains a pointer.",
            )
        }
        BlockLayout(programLocationContext.program, programLocationContext.address)
            .apply {
                // TODO: Determine if we can get this to be undone with a single undo command instead of several.
                programLocationContext.program.withTransaction<Exception>("update program") { updateProgram() }
            }
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean = context is ProgramLocationActionContext
}
