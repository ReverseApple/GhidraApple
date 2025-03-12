package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.decompiler.DecompInterface
import ghidra.framework.cmd.BackgroundCommand
import ghidra.framework.cmd.Command
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.StackReference
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.getOutputBytes
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ApplyNSConcreteGlobalBlock(
    val address: Address,
) : Command<Program> {
    private var errorMsg: String? = null

    override fun applyTo(program: Program): Boolean {
        if (BlockLayoutDataType.isAddressBlockLayout(program, address)) return false
        val blockLayout = BlockLayout(program, address)
        // We use these to propagate types and such. If we don't have them, something probably went wrong.
        if (blockLayout.flagsBitfield == 0 || blockLayout.descriptorPointer == 0L) {
            errorMsg = "Global block at $address is missing flags and/or descriptor!"
            return false
        }
        DataUtilities.createData(
            program,
            address,
            blockLayout.toDataType(),
            -1,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
        )
        blockLayout.markupAdditionalTypes()

        return true
    }

    override fun getStatusMsg(): String? = errorMsg

    override fun getName(): String = "Mark Global Block at 0x$address"
}

/**
 *
 * This is a [BackgroundCommand] because it uses the decompiler internally,
 * and that might take longer than we want to block the UI thread.
 *
 */
class ApplyNSConcreteStackBlock(
    val function: Function,
    val instruction: Instruction,
) : BackgroundCommand<Program>() {
    constructor(function: Function, address: Address) : this(function, function.program.listing.getInstructionAt(address))

    constructor(program: Program, address: Address) : this(program.listing.getFunctionContaining(address), address)

    override fun applyTo(
        program: Program,
        monitor: TaskMonitor,
    ): Boolean {
        if (BlockLayoutDataType.isAddressBlockLayout(program, instruction.address)) return false
        // TODO: Too many nested lambdas that make it hard to follow what `it` is referring to at any given time.
        val instructionsThatBuildTheStackBlock =
            // Start with the first instruction.
            generateSequence(instruction) {
                program.listing.getInstructionAfter(it.address).let { nextInstruction ->
                    if (nextInstruction.mnemonicString == "b") {
                        // If the next instruction is a branch instruction, skip it and instead append the
                        //  instruction that it is branching to.
                        program.listing.getInstructionAt(it.pcode[0].inputs[0].address)
                    } else {
                        // Otherwise just append the instruction as-is.
                        it
                    }
                }
            }.takeWhile { instructionToTake ->
                // Continue taking instructions as long as we are in the same function.
                program.listing.getFunctionContaining(instructionToTake.address)?.name == function.name &&
                    // If we hit a jump or call instruction, we're likely done with building the block. It's
                    //  unlikely that the compiler would put a jump in the middle of block-building code.
                    instructionToTake.flowType?.let { !it.isJump && !it.isCall } == true
            }.toList()

        // TODO: This seems possible to write more elegantly
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
        //  stack block. We'll use it to type that part of the function's stack frame.
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
            function.stackFrame.createVariable(
                "block_${program.address(invokePointer)}",
                baseStackOffset,
                toDataType(),
                SourceType.ANALYSIS,
            )
            markupAdditionalTypes()
        }
        // TODO: Maybe perform a second pass to get better typing for the imported variables.
        return true
    }
}
