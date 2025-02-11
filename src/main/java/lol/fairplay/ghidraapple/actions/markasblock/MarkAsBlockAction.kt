package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.decompiler.DecompilerLocation
import ghidra.app.emulator.EmulatorHelper
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.Pointer
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.StackReference
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MarkAsBlockAction : DockingAction("Mark As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(actionContext: ActionContext?) {
        val typedContext =
            actionContext as? ProgramLocationActionContext ?: return

        when (typedContext) {
            is CodeViewerActionContext -> handleDisassemblerLocation(typedContext)
            is DecompilerActionContext -> handleDecompilerLocation(typedContext)
        }
    }

    private fun handleDisassemblerLocation(context: CodeViewerActionContext) {
        val dataAtLocation =
            context.program.listing.getDataAt(context.address)
                ?: throw IllegalArgumentException(
                    "No data at address 0x${context.address}. " +
                        "Please use the Decompile pane if marking a stack block.",
                )

        if (BlockLayoutDataType.isDataTypeBlockType(dataAtLocation.dataType)) {
            throw IllegalArgumentException("The data at address 0x${context.address} is already a block.")
        }

        if (dataAtLocation.dataType !is Pointer) {
            throw IllegalArgumentException(
                "The address 0x${context.address} does not contain a pointer. " +
                    "This is probably not a block. Please start with an address that contains a pointer.",
            )
        }

        BlockLayout(context.program, context.address)
            .apply {
                // TODO: Determine if we can get this to be undone with a single undo command instead of several.
                context.program.withTransaction<Exception>("update program") {
                    DataUtilities.createData(
                        context.program,
                        context.address,
                        toDataType(),
                        -1,
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                    )
                    updateProgram()
                }
            }
    }

    private fun handleDecompilerLocation(context: DecompilerActionContext) {
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
                ?.let { BlockLayoutDataType.isDataTypeBlockType(it) } == true
        ) {
            throw IllegalArgumentException(
                "Variable at stack offset ${stackReference.stackOffset} is already a block.",
            )
        }

        /**
         * We will use the result of this function to start emulating the function as it builds up the stack
         *  block. The function this is within should be triggered from the first decompilation line for the
         *  building of the stack block. However, the relevant assembly instructions may extend earlier than
         *  the contextual address. So, we find the preceding decompilation line and calculate the very next
         *  instruction after its instruction and return that. This hopefully ensures that our emulator will
         *  correctly build the relevant portions of the stack block in its emulated stack.
         */
        val firstRelevantInstructionAddress =
            {
                // For some reason, the line number in [context] is more accurate than the one in [decompilerLocation].
                val precedingLineNumber = context.lineNumber - 1

                // We have to iterate through the tokens for one with the line parent we want, and then take the parent.
                val precedingLine =
                    decompilerLocation.decompile.cCodeMarkup
                        .tokenIterator(true)
                        .iterator()
                        .asSequence()
                        .firstOrNull { it.lineParent?.lineNumber == precedingLineNumber }
                        ?.lineParent
                        ?: throw IllegalStateException("Could not find preceding line $precedingLineNumber in $function.")

                val precedingLineMaxAddress =
                    precedingLine.allTokens.maxByOrNull { it.maxAddress ?: context.program.minAddress }?.maxAddress
                        ?: throw IllegalStateException(
                            "Could not find the max address for preceding line $precedingLineNumber in $function.",
                        )

                val lastPrecedingInstruction =
                    context.program.listing.getInstructionAt(precedingLineMaxAddress)
                        ?: throw IllegalStateException(
                            "Failed to read preceding instruction at $precedingLineMaxAddress.",
                        )

                precedingLineMaxAddress.offset + lastPrecedingInstruction.length
            }()

        // This is an older API, but the newer [PcodeEmulator] API is honestly a bit overkill for our purposes here.
        val helper = EmulatorHelper(context.program)
        helper.emulator.setExecuteAddress(firstRelevantInstructionAddress)
        var instructionsExecuted = 0
        do {
            helper.emulator.executeInstruction(false, null)
            instructionsExecuted += 1
            // Most stack blocks are built using a low-double-digit amount of instructions, so this maximum is likely
            //  much higher than necessary, but it should be ok to give at least some room to grow for edge cases.
            if (instructionsExecuted > 100) {
                throw IllegalStateException("Too many potential stack block building instructions found!")
            }

            fun isBlockFinishedBeingBuilt(): Boolean {
                val nextInstruction =
                    context.program.listing
                        // We get the offset of the execute address and re-contextualize it within our program.
                        .getInstructionAt(context.program.address(helper.emulator.executeAddress.offset))
                        // If we ever fail to find the next instruction, just return true to break out of the loop.
                        ?: return true

                // Execute until we hit a jump or call. This is probably the end of the block setup code.
                return nextInstruction.flowType.let { it.isJump || it.isCall }
            }
        } while (!isBlockFinishedBeingBuilt())

        // The stack reference gives us a negative offset relative to the function's stack frame, but we need to
        //  make it positive in order to read from our emulated stack.
        val positiveStackOffset = function.stackFrame.frameSize + stackReference.stackOffset

        val minimalBlockType =
            BlockLayoutDataType.minimalBlockType(context.program.dataTypeManager)

        val stackBlockBytes =
            helper
                .readStackValue(positiveStackOffset, minimalBlockType.length, false)
                // The above returns a BigInteger, which we don't want, so we need to convert it to a ByteArray.
                .toByteArray()
                // The above also doesn't bother with leading zeros (as it thinks we want a number), so we have
                //  to add any zero bytes back onto the beginning.
                .let {
                    val remainingBytes = minimalBlockType.length - it.size
                    // TODO: Confirm that ByteArray(n) is guaranteed to contain only null bytes.
                    if (remainingBytes != 0) ByteArray(remainingBytes) + it else it
                }
                // We need to reverse the array if we are in little-endian territory.
                .let { if (context.program.memory.isBigEndian) it else it.reversed().toByteArray() }

        BlockLayout(
            context.program,
            ByteBuffer.wrap(stackBlockBytes).order(ByteOrder.LITTLE_ENDIAN),
            context.program.address(firstRelevantInstructionAddress).toString(),
        ).apply {
            // TODO: Determine if we can get this to be undone with a single undo command instead of several.
            context.program.withTransaction<Exception>("update program") {
                function.stackFrame.createVariable(
                    "block_${context.program.address(invokePointer)}",
                    stackReference.stackOffset,
                    toDataType(),
                    SourceType.ANALYSIS,
                )
                updateProgram()
            }
        }
        // TODO: Maybe perform a second pass to get better typing for the imported variables.
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean = context is ProgramLocationActionContext
}
