package lol.fairplay.ghidraapple.actions.setasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.program.model.data.Pointer
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout

class SetAsBlockAction : DockingAction("Set As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(actionContext: ActionContext?) {
        val typedContext =
            actionContext as? ProgramLocationActionContext ?: return

        when (typedContext) {
            // TODO: Maybe handle cases where the address of an instruction is right clicked.
            is CodeViewerActionContext -> handleDisassemblerLocation(typedContext)
            is DecompilerActionContext -> handleDecompilerLocation(typedContext)
        }
    }

    private fun handleDisassemblerLocation(context: CodeViewerActionContext) {
        val dataAtLocation =
            context.program.listing.getDataAt(context.address)
                ?: throw IllegalArgumentException(
                    "No data at address 0x${context.address}. Please operate only on data. " +
                        // TODO: Support stack blocks.
                        "Stack blocks are not yet supported.",
                )
        if (dataAtLocation.dataType !is Pointer) {
            throw IllegalArgumentException(
                "The address 0x${context.address} does not contain a pointer. " +
                    "This is probably not a block. Please start with an address that contains a pointer.",
            )
        }

        BlockLayout(context.program, context.address)
            .apply {
                // TODO: Determine if we can get this to be undone with a single undo command instead of several.
                context.program.withTransaction<Exception>("update program") { updateProgram() }
            }
    }

    private fun handleDecompilerLocation(context: DecompilerActionContext): Unit =
        throw IllegalArgumentException(
            "Stack blocks are not support yet. Please perform this action from the Listing panel.",
        )

    override fun isEnabledForContext(context: ActionContext?): Boolean = context is ProgramLocationActionContext
}
