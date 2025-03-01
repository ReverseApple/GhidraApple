package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.StackReference
import ghidra.util.Msg
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.getOutputBytes
import java.nio.ByteBuffer
import java.nio.ByteOrder

fun markGlobalBlock(
    program: Program,
    address: Address,
) {
    if (BlockLayoutDataType.isAddressBlockLayout(program, address)) return
    BlockLayout(program, address)
        .apply {
            // We use these to propagate types and such. If we don't have them, something probably went wrong.
            if (flagsBitfield == 0 || descriptorPointer == 0L) {
                throw IllegalStateException("Global block at $address is missing flags and/or descriptor!")
            }
            Msg.info(this, "Marking global block at 0x$address.")
            program.withTransaction<Exception>("Mark Global Block at 0x$address") {
                DataUtilities.createData(
                    program,
                    address,
                    toDataType(),
                    -1,
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                )
                markupAdditionalTypes()
            }
        }
}

fun markStackBlock(
    program: Program,
    function: Function,
    instruction: Instruction,
) {
    if (BlockLayoutDataType.isAddressBlockLayout(program, instruction.address)) return
    val instructionsThatBuildTheStackBlock =
        generateSequence(instruction) { program.listing.getInstructionAfter(it.address) }
            .takeWhile {
                program.listing.getFunctionContaining(it.address)?.name == function.name &&
                    // If we hit a jump or call instruction, we're likely done with building the block. It's
                    //  unlikely that the compiler would put a jump in the middle of block-building code.
                    it.flowType?.let { !it.isJump && !it.isCall } == true
            }.toList()

    val decompileResults =
        DecompInterface()
            .let { decompiler ->
                decompiler.simplificationStyle = "normalize"
                decompiler.openProgram(program)
                decompiler
                    .decompileFunction(function, 30, null)
                    .also { decompiler.dispose() }
            }

    // This is the offset into the function's stack frame where the actual program will write the
    //  stack block. We'll use it we'll use to type that part of the function's stack frame.
    val baseStackOffset =
        instruction.referencesFrom
            .filterIsInstance<StackReference>()
            .first()
            .stackOffset

    val minimalBlockLayoutSize =
        BlockLayoutDataType.minimalBlockType(program.dataTypeManager).length

    val stackBlockByteArray = ByteArray(minimalBlockLayoutSize)

    instructionsThatBuildTheStackBlock.forEach { iteratedInstruction ->
        decompileResults.highFunction.pcodeOps
            .iterator()
            .asSequence()
            .filter { it.seqnum.target == iteratedInstruction.address }
            .forEach pcodeops_loop@{
                // If the output is not a stack address, skip it.
                if (it.output?.address?.isStackAddress != true) return@pcodeops_loop
                val positiveOffset = it.output.address.offset - baseStackOffset
                // If the offset isn't within the range for our stack block, skip it.
                if (positiveOffset < 0 || positiveOffset >= minimalBlockLayoutSize) return@pcodeops_loop
                // If we can get the output bytes from the pcode operation, copy them into our stack.
                it.getOutputBytes(program)?.copyInto(stackBlockByteArray, positiveOffset.toInt())
            }
    }

    BlockLayout(
        program,
        ByteBuffer.wrap(stackBlockByteArray).order(ByteOrder.LITTLE_ENDIAN),
        instruction.address.toString(),
    ).apply {
        // We use these to propagate types and such. If we don't have them, something probably went wrong.
        if (flagsBitfield == 0 || descriptorPointer == 0L) {
            throw IllegalStateException("Stack block at ${instruction.address} is missing flags and/or descriptor!")
        }
        Msg.info(this, "Marking stack block at 0x${instruction.address}")
        program.withTransaction<Exception>("Mark Stack Block at 0x${instruction.address}") {
            function.stackFrame.createVariable(
                "block_${program.address(invokePointer)}",
                baseStackOffset,
                toDataType(),
                SourceType.ANALYSIS,
            )
            markupAdditionalTypes()
        }
    }
    // TODO: Maybe perform a second pass to get better typing for the imported variables.
}
