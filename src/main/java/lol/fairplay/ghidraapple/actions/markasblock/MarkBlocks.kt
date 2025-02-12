package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.decompiler.DecompilerLocation
import ghidra.app.emulator.EmulatorHelper
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.StackReference
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockFlag
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

fun markGlobalBlock(
    program: Program,
    address: Address,
) {
    BlockLayout(program, address)
        .apply {
            // The [BlockLayout] constructor does some minimal checks to where we can be fairly certain that
            //  what we just parsed was, in fact, a block layout. However, it shouldn't hurt to perform some
            //  additional checks. We expect this to be a global block, so if the parsed flags have that bit
            //  set, that's more assurance that we parsed a block layout, and it's global as expected. After
            //  that, we can finally mark up the program and invoke function with the data types.
            if (BlockFlag.BLOCK_IS_GLOBAL !in flags) throw IOException("This is not a global block.")
            // TODO: Determine if we can get this to be undone with a single undo command instead of several.
            program.withTransaction<Exception>("update program") {
                DataUtilities.createData(
                    program,
                    address,
                    toDataType(),
                    -1,
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                )
                updateProgram()
            }
        }
}

fun markStackBlock(
    program: Program,
    function: Function,
    lineNumber: Int,
    decompilerLocation: DecompilerLocation,
    stackReference: StackReference,
) {
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
            val precedingLineNumber = lineNumber - 1

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
                precedingLine.allTokens.maxByOrNull { it.maxAddress ?: program.minAddress }?.maxAddress
                    ?: throw IllegalStateException(
                        "Could not find the max address for preceding line $precedingLineNumber in $function.",
                    )

            val lastPrecedingInstruction =
                program.listing.getInstructionAt(precedingLineMaxAddress)
                    ?: throw IllegalStateException(
                        "Failed to read preceding instruction at $precedingLineMaxAddress.",
                    )

            precedingLineMaxAddress.offset + lastPrecedingInstruction.length
        }()

    // This is an older API, but the newer [PcodeEmulator] API is honestly a bit overkill for our purposes here.
    val helper = EmulatorHelper(program)
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
                program.listing
                    // We get the offset of the execute address and re-contextualize it within our program.
                    .getInstructionAt(program.address(helper.emulator.executeAddress.offset))
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
        BlockLayoutDataType.minimalBlockType(program.dataTypeManager)

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
            .let { if (program.memory.isBigEndian) it else it.reversed().toByteArray() }

    BlockLayout(
        program,
        ByteBuffer.wrap(stackBlockBytes).order(ByteOrder.LITTLE_ENDIAN),
        program.address(firstRelevantInstructionAddress).toString(),
    ).apply {
        // TODO: Determine if we can get this to be undone with a single undo command instead of several.
        program.withTransaction<Exception>("update program") {
            function.stackFrame.createVariable(
                "block_${program.address(invokePointer)}",
                stackReference.stackOffset,
                toDataType(),
                SourceType.ANALYSIS,
            )
            updateProgram()
        }
    }
    // TODO: Maybe perform a second pass to get better typing for the imported variables.
}
