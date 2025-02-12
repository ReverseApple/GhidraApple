package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.decompiler.DecompilerLocation
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.program.model.data.Pointer
import ghidra.program.model.symbol.StackReference
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType

class MarkAsBlockAction : DockingAction("Mark As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(actionContext: ActionContext?) {
        val typedContext =
            actionContext as? ProgramLocationActionContext ?: return

        when (typedContext) {
            is CodeViewerActionContext -> handleDisassemblyLocation(typedContext)
            is DecompilerActionContext -> handleDecompilationLocation(typedContext)
        }
    }

    /**
     * Ran when the user selects the action from an address in the disassembly. Performs some sanity
     *  checks on the context before passing to the function that actually handles the block.
     */
    private fun handleDisassemblyLocation(context: CodeViewerActionContext) {
        val dataAtLocation =
            context.program.listing.getDataAt(context.address)
                ?: throw IllegalArgumentException(
                    "No data at address 0x${context.address}. " +
                        "Please use the Decompile pane if marking a stack block.",
                )

        if (BlockLayoutDataType.isDataTypeBlockLayoutType(dataAtLocation.dataType)) {
            throw IllegalArgumentException("The data at address 0x${context.address} is already a block.")
        }

        if (dataAtLocation.dataType !is Pointer) {
            throw IllegalArgumentException(
                "The address 0x${context.address} does not contain a pointer. " +
                    "This is probably not a block. Please start with an address that contains a pointer.",
            )
        }

        markGlobalBlock(context.program, context.address)
    }

    /**
     * Ran when the user selects the action from a location in the decompilation. Performs some sanity
     *  checks on the context before passing to the function that actually handles the block.
     */
    private fun handleDecompilationLocation(context: DecompilerActionContext) {
        val function =
            context.program.listing.getFunctionContaining(context.address)
                ?: throw IllegalArgumentException(
                    "Address 0x${context.address} is not part of a function.",
                )

        val decompilerLocation =
            context.location as? DecompilerLocation
                ?: throw IllegalStateException(
                    "Received a DecompilerActionContext with a non-DecompilerLocation location.",
                )

        val selectedInstruction =
            context.program.listing.getInstructionAt(context.address)
                ?: throw IllegalArgumentException("Address 0x${context.address} does not contain an instruction.")

        // We're basically assuming this is a stack block at this point, so we ensure this is a stack-y instruction.
        val stackReference =
            selectedInstruction.referencesFrom.filterIsInstance<StackReference>().firstOrNull()
                ?: throw IllegalArgumentException(
                    "The instruction at address 0x${context.address} does not operate on the stack. " +
                        "This is probably not a stack block. " +
                        "Please start with an instruction that operates on the stack.",
                )

        if (
            function
                .stackFrame
                .stackVariables
                .firstOrNull { it.stackOffset == stackReference.stackOffset }
                ?.dataType
                ?.let { BlockLayoutDataType.isDataTypeBlockLayoutType(it) } == true
        ) {
            throw IllegalArgumentException(
                "Variable at stack offset ${stackReference.stackOffset} is already a block.",
            )
        }

        markStackBlock(
            context.program,
            function,
            // For some reason, the line number in [context] is more accurate than the one in [decompilerLocation].
            context.lineNumber,
            decompilerLocation,
            stackReference,
        )
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean = context is ProgramLocationActionContext
}
