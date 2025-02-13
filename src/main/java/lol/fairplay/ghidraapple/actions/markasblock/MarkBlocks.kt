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
    // These instructions will be looped over with two simultaneous passes to build up the likely stack state.
    val instructions =
        generateSequence(instruction) { program.listing.getInstructionAfter(it.address) }
            .takeWhile {
                program.listing.getFunctionContaining(it.address)?.name == function.name &&
                    program.listing
                        .getInstructionAfter(it.address)
                        ?.flowType
                        ?.let { !it.isJump && !it.isCall } == true
            }

    // Emulated stack

    // This is the offset where out emulator will write the stack block. The given instruction should
    //  be a store instruction that writes the first field the block into the stack. It may sometimes
    //  include a scalar that is summed with the value of the stack pointer to create the destination
    //  address. Since the emulator starts with a stack pointer value of zero, we can use this scalar
    //  (if it exits) to determine where in the emulator's memory to look for the stack block.
    val emulatedStackOffset =
        instruction.getOpObjects(1).let {
            (it.getOrNull(1) as? Scalar)?.value ?: 0
        }

    // This is an older API, but the newer [PcodeEmulator] API is honestly a bit overkill for our purposes here.
    val helper = EmulatorHelper(program)
    helper.emulator.setExecuteAddress(instructions.first().address.offset)

    // This is the offset into the function's stack frame where the actual program will write the
    //  stack block. We'll use it we'll use to type that part of the function's stack frame.
    val trueStackOffset =
        instruction.referencesFrom
            .filterIsInstance<StackReference>()
            .first()
            .stackOffset

    val minimalBlockLayoutSize =
        BlockLayoutDataType.minimalBlockType(program.dataTypeManager).length

    val stackReferenceByteList = mutableListOf<Byte>()

    run instructionLoop@{
        instructions.forEach { instruction ->
            helper.emulator.setExecuteAddress(instruction.address.offset)
            try {
                helper.emulator.executeInstruction(false, null)
            } catch (_: Exception) {
                // Silently fail if the emulator couldn't execute the instruction. It hopefully
                //  wasn't important enough to where we would break things by skipping it.
            }
            // Use the references to build up another copy of the stack.
            instruction.referencesFrom.let { references ->
                if (references.isEmpty()) return@let
                val (stackReference, otherReferences) =
                    instruction.referencesFrom.toList().let {
                        val stackReference = it.filterIsInstance<StackReference>().firstOrNull()
                        Pair(stackReference, it.filterNot { it == stackReference })
                    }
                if (stackReference != null) {
                    when {
                        otherReferences.isEmpty() -> {
                            // This (probably) only happens when writing the flags to the stack. Our emulator
                            //  should help cover the gaps there. In any case, assume we're trying to write a
                            //  long-sized data block to the stack and write an empty list of bytes.
                            stackReferenceByteList += ByteArray(Long.SIZE_BYTES).toList()
                        }
                        else ->
                            otherReferences.forEach {
                                stackReferenceByteList +=
                                    ByteBuffer
                                        .allocate(Long.SIZE_BYTES)
                                        .order(ByteOrder.LITTLE_ENDIAN)
                                        .putLong(it.toAddress.offset)
                                        .array()
                                        .toList()
                            }
                    }
                } else {
                    // TODO: Do we need to do anything here?
                }
            }
            // If our stack-reference-built stack byte list is the right size, break out of the loop.
            if (stackReferenceByteList.size == minimalBlockLayoutSize) return@instructionLoop
        }
    }

    // Get the stack we built up from references.
    val stackReferenceBlockBytes = stackReferenceByteList.toByteArray()

    // Get the state of the stack in our emulator.
    val emulatedStackBlockBytes =
        helper
            .readStackValue(emulatedStackOffset.toInt(), minimalBlockLayoutSize, false)
            // The above returns a BigInteger, which we don't want, so we need to convert it to a ByteArray.
            .toByteArray()
            // The above also doesn't bother with leading zeros (as it thinks we want a number), so we have
            //  to add any zero bytes back onto the beginning.
            .let {
                val remainingBytes = minimalBlockLayoutSize - it.size
                // TODO: Confirm that ByteArray(n) is guaranteed to contain only null bytes.
                if (remainingBytes != 0) ByteArray(remainingBytes) + it else it
            }
            // We need to reverse the array if we are in little-endian territory.
            .let { if (program.memory.isBigEndian) it else it.reversed().toByteArray() }

    // Ensure they are the same length.
    assert(stackReferenceBlockBytes.size == emulatedStackBlockBytes.size)

    // Put them into byte buffers
    val stackReferenceStackBlockBuffer =
        ByteBuffer.wrap(stackReferenceBlockBytes).order(ByteOrder.LITTLE_ENDIAN)
    val emulatedStackBlockBuffer =
        ByteBuffer.wrap(emulatedStackBlockBytes).order(ByteOrder.LITTLE_ENDIAN)

    // Loop over them, putting non-zero long-sized chunks into the result buffer.

    val resultBuffer =
        ByteBuffer.allocate(minimalBlockLayoutSize).order(ByteOrder.LITTLE_ENDIAN)

    for (i in 0 until minimalBlockLayoutSize step Long.SIZE_BYTES) {
        val stackReferenceLong = stackReferenceStackBlockBuffer.getLong(i)
        val emulatedStackLong = emulatedStackBlockBuffer.getLong(i)
        resultBuffer.putLong(
            when {
                // Prefer the chunks from the reference-built stack over the ones from the emulated stack.
                stackReferenceLong != 0L -> stackReferenceLong
                emulatedStackLong != 0L -> emulatedStackLong
                else -> 0
            },
        )
    }

    // Finally build and markup the stack block.

    BlockLayout(
        program,
        resultBuffer.position(0),
        instruction.address.toString(),
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
