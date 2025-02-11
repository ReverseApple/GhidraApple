package lol.fairplay.ghidraapple.actions.setasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext
import ghidra.program.model.data.Pointer
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout

class SetAsBlockAction : DockingAction("Set As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(actionContext: ActionContext?) {
        val typedContext =
            // TODO: Allow [DecompilerActionContext] for stack blocks when implementing support for them.
            actionContext as? CodeViewerActionContext ?: return
        val dataAtLocation =
            typedContext.program.listing.getDataAt(typedContext.address)
                ?: throw IllegalArgumentException(
                    "No data at address 0x${typedContext.address}. Please operate only on data. " +
                        // TODO: Support stack blocks.
                        "Stack blocks are not yet supported.",
                )
        if (dataAtLocation.dataType !is Pointer) {
            throw IllegalArgumentException(
                "The address 0x${typedContext.address} does not contain a pointer. " +
                    "This is probably not a block. Please start with an address that contains a pointer.",
            )
        }
        BlockLayout(typedContext.program, typedContext.address)
            .apply {
                // TODO: Determine if we can get this to be undone with a single undo command instead of several.
                typedContext.program.withTransaction<Exception>("update program") { updateProgram() }
            }
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean = context is CodeViewerActionContext
}
