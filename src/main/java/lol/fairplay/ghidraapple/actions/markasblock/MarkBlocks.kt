package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.decompiler.DecompInterface
import ghidra.framework.cmd.BackgroundCommand
import ghidra.framework.cmd.Command
import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.StackReference
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BLOCK_CATEGORY_PATH_STRING
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.doesReferenceStackBlockSymbol
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.isAddressBlockLayout
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.getAddressesOfSymbol
import lol.fairplay.ghidraapple.analysis.utilities.getOutputBytes
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MarkNSConcreteGlobalBlock(
    val address: Address,
) : Command<Program> {
    override fun getName(): String = "Mark Global Block at 0x$address"

    private var errorMsg: String? = null

    override fun getStatusMsg(): String? = errorMsg

    override fun applyTo(program: Program): Boolean {
        // If the address is already marked as a block, don't do it again.
        if (program.isAddressBlockLayout(address)) return false

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
}

/**
 * This command will mark a stack block at the given address.
 *
 * This is a [BackgroundCommand] because it uses the decompiler internally,
 * and that might take longer than we want to block the UI thread.
 */
class MarkNSConcreteStackBlock(
    val function: Function,
    val instruction: Instruction,
) : BackgroundCommand<Program>() {
    constructor(function: Function, address: Address) : this(function, function.program.listing.getInstructionAt(address))

    constructor(program: Program, address: Address) : this(program.listing.getFunctionContaining(address), address)

    override fun getName(): String = "Mark Stack Block at 0x${instruction.address}"

    override fun applyTo(
        program: Program,
        monitor: TaskMonitor,
    ): Boolean {
        // If the address is already marked as a block, don't do it again.
        if (program.isAddressBlockLayout(instruction.address)) return false

        // At the start of every stack block, there should be instructions that load a pointer to the stack block
        //  symbol into a register, and then, later, instructions to store it to the stack. This command is meant
        //  to be used with either the specific load instruction or the specific store instruction.

        val instructionsThatBuildTheStackBlock =
            // Start with the first instruction.
            generateSequence(instruction) { currentInstruction ->
                program.listing.getInstructionAfter(currentInstruction.address).let { nextInstruction ->
                    if (nextInstruction.mnemonicString == "b") {
                        // If the next instruction is a branch instruction, skip it and instead append the
                        //  instruction that it is branching to.
                        program.listing.getInstructionAt(nextInstruction.pcode[0].inputs[0].address)
                    } else {
                        // Otherwise just append the next instruction as-is.
                        nextInstruction
                    }
                }
            }.takeWhile { instructionToTake ->
                // Continue taking instructions as long as we are in the same function.
                program.listing.getFunctionContaining(instructionToTake.address)?.name == function.name &&
                    // If we hit a jump or call instruction, we're likely done with building the block. It's
                    //  unlikely that the compiler would put a jump in the middle of block-building code.
                    instructionToTake.flowType?.let { !it.isJump && !it.isCall } == true
            }.toList()

        // If we're here from the load instruction, we will save the result register for reference.
        val loadRegister: Register? =
            instruction
                .takeIf {
                    it.pcode.any { it.opcode == PcodeOp.LOAD }
                }?.resultObjects
                ?.first { it is Register } as Register?

        val minimalBlockLayoutType =
            BlockLayoutDataType(
                program.dataTypeManager,
                "${instruction.address}_minimal",
                "${instruction.address}_minimal",
            )

        val minimalBlockLayoutSize = minimalBlockLayoutType.length

        // This will contain the stack block as it would appear on the stack.
        val stackBlockByteArray = ByteArray(minimalBlockLayoutSize)

        // TODO: This seems possible to write more elegantly
        val decompileResults =
            DecompInterface()
                .let { decompiler ->
                    decompiler.simplificationStyle = "normalize"
                    decompiler.openProgram(program)
                    decompiler
                        .decompileFunction(function, 30, monitor)
                        .also { decompiler.dispose() }
                }

        var baseStackOffset: Long? = null

        val stackBlockSymbolAddresses =
            program.getAddressesOfSymbol("__NSConcreteStackBlock") + program.getAddressesOfSymbol("__NSStackBlock__")

        // This will be a map of all the stack writes made by the instructions.
        val stackOffsetToBytesMap: MutableMap<Long, ByteArray> = mutableMapOf()

        instructionsThatBuildTheStackBlock.forEach { iteratedInstruction ->
            decompileResults.highFunction.pcodeOps
                .iterator()
                .asSequence()
                .filter { it.seqnum.target == iteratedInstruction.address }
                .forEach pcodeops_loop@{ pcodeOp ->
                    // If the output is not a stack address, skip it.
                    if (pcodeOp.output?.address?.isStackAddress != true) return@pcodeops_loop
                    val stackOffset = pcodeOp.output.address.offset
                    baseStackOffset?.let { base ->
                        val positiveOffset = stackOffset - base
                        // If the offset isn't within the range for our stack block, skip it.
                        if (positiveOffset < 0 || positiveOffset >= minimalBlockLayoutSize) return@pcodeops_loop
                    }
                    pcodeOp.getOutputBytes(program)?.let { bytes ->
                        stackOffsetToBytesMap[stackOffset] = bytes
                        if (bytes.size == Long.SIZE_BYTES) {
                            val bytesAsLong =
                                ByteBuffer
                                    .allocate(bytes.size)
                                    .order(
                                        if (program.memory.isBigEndian) {
                                            ByteOrder.BIG_ENDIAN
                                        } else {
                                            ByteOrder.LITTLE_ENDIAN
                                        },
                                    ).put(bytes)
                                    .flip()
                                    .long
                            // If the storage of the stack block pointer is split across multiple writes, this
                            //  check will not work. We fall back to stack references below.
                            if (stackBlockSymbolAddresses.any { it.offset == bytesAsLong }) {
                                baseStackOffset = stackOffset
                            }
                        }
                    }
                }
        }

        // Since [baseOffset] is captured by the above lambda, the Kotlin compiler will complain if
        //  we try to use it directly. We must store it as an immutable value.
        val safeBaseStackOffset =
            baseStackOffset
                // Last-ditch effort to find the stack offset for the stack block. This covers
                //  cases where the PCode is weird (see the comment in the lambda above).
                ?: instructionsThatBuildTheStackBlock
                    .firstOrNull {
                        it.doesReferenceStackBlockSymbol && it.pcode.count { it.opcode == PcodeOp.STORE } == 1
                    }?.referencesFrom
                    ?.filterIsInstance<StackReference>()
                    ?.firstOrNull()
                    ?.stackOffset
                    ?.toLong()

        if (safeBaseStackOffset == null) {
            statusMsg = "Failed to find the base stack offset for the stack block at ${instruction.address}!"
            return false
        }

        // Initially mark the stack address as a minimal block. If the decompilation and/or parsing
        //  fails, at least we will have something to show the user.
        function.stackFrame.createVariable(
            "block_minimal_${instruction.address}",
            safeBaseStackOffset.toInt(),
            minimalBlockLayoutType,
            SourceType.ANALYSIS,
        )

        // Now we go over the recovered stack writes and build up the stack block.
        stackOffsetToBytesMap.forEach { (offset, bytes) ->
            val positiveOffset = offset - safeBaseStackOffset
            // If the offset isn't within the range for our stack block, skip it.
            if (positiveOffset < 0 || positiveOffset >= minimalBlockLayoutSize) return@forEach
            bytes.copyInto(stackBlockByteArray, positiveOffset.toInt())
        }

        BlockLayout(
            program,
            ByteBuffer.wrap(stackBlockByteArray).order(ByteOrder.LITTLE_ENDIAN),
            instruction.address.toString(),
        ).apply {
            // We use these to propagate types and such. If we don't have them, something probably went wrong.
            if (flagsBitfield == 0 || descriptorPointer == 0L) {
                // TODO: Does setting this message really do anything if we aren't making this a failure state?
                statusMsg = "Stack block at ${instruction.address} is missing flags and/or descriptor!"
                // We say the command "worked", because at least the minimal type should be applied.
                return true
            }

            if (program.functionManager.getFunctionContaining(program.address(descriptorPointer)) != null) {
                // TODO: Does setting this message really do anything if we aren't making this a failure state?
                statusMsg = "Stack block at ${instruction.address} has a descriptor address that is inside a function!"
                // We say the command "worked", because at least the minimal type should be applied.
                return true
            }

            // Now that we know we have a good block type, we mark it up.
            Msg.info(this, "Marking stack block at 0x${instruction.address}")
            function.stackFrame.createVariable(
                "block_${program.address(invokePointer)}",
                safeBaseStackOffset.toInt(),
                toDataType(),
                SourceType.ANALYSIS,
            )
            markupAdditionalTypes()

            // We don't need the minimal type now that we have the more complete type. Remove it.
            program.dataTypeManager.apply {
                // Yes, we do need to call [getDataType] and get another instance. Calling [remove] with
                //  the existing instance does not work, unfortunately.
                remove(
                    getDataType(CategoryPath(BLOCK_CATEGORY_PATH_STRING), minimalBlockLayoutType.name),
                    TaskMonitor.DUMMY,
                )
            }
        }
        // TODO: Maybe perform a second pass to get better typing for the imported variables.

        return true
    }
}
