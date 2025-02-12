package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.emulator.EmulatorHelper
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.StackReference
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import java.nio.ByteBuffer
import java.nio.ByteOrder

fun markGlobalBlock(
    program: Program,
    address: Address,
) {
    BlockLayout(program, address)
        .apply {
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
    instruction: Instruction,
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

        generateSequence(instruction) { currentInstruction ->
            program.listing.getInstructionBefore(currentInstruction.address)
        }.take(50)
            .takeWhile {
                it.flowType?.let { !it.isJump && !it.isCall && !it.isTerminal } == true
            }.lastOrNull()
            ?.address
            ?.offset ?: throw IllegalStateException("Failed to find start of stack block building instructions.")

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
            return nextInstruction.flowType.let { it.isJump || it.isCall || it.isTerminal }
        }
    } while (!isBlockFinishedBeingBuilt())

    // This is the offset into the function's stack frame where the actual program will write the
    //  stack block. We'll use it we'll use to type that part of the function's stack frame.
    val trueStackOffset =
        instruction.referencesFrom
            .filterIsInstance<StackReference>()
            .first()
            .stackOffset

    // This is the offset where out emulator will write the stack block. The given instruction should
    //  be a store instruction that writes the first field the block into the stack. It may sometimes
    //  include a scalar that is summed with the value of the stack pointer to create the destination
    //  address. Since the emulator starts with a stack pointer value of zero, we can use this scalar
    //  (if it exits) to determine where in the emulator's memory to look for the stack block.
    val emulatedStackOffset =
        instruction.getOpObjects(1).let {
            if (it[0] != program.getRegister("sp")) {
                throw IllegalArgumentException("Cannot calculate stack offset.")
            }
            (it.getOrNull(1) as? Scalar)?.value ?: 0
        }

    val minimalBlockLength =
        BlockLayoutDataType.minimalBlockType(program.dataTypeManager).length

    val stackBlockBytes =
        helper
            .readStackValue(emulatedStackOffset.toInt(), minimalBlockLength, false)
            // The above returns a BigInteger, which we don't want, so we need to convert it to a ByteArray.
            .toByteArray()
            // The above also doesn't bother with leading zeros (as it thinks we want a number), so we have
            //  to add any zero bytes back onto the beginning.
            .let {
                val remainingBytes = minimalBlockLength - it.size
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
                trueStackOffset,
                toDataType(),
                SourceType.ANALYSIS,
            )
            updateProgram()
        }
    }
    // TODO: Maybe perform a second pass to get better typing for the imported variables.
}
