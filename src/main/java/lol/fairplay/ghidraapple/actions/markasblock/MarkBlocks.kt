package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.decompiler.DecompInterface
import ghidra.framework.cmd.BackgroundCommand
import ghidra.framework.cmd.Command
import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOpAST
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BLOCK_CATEGORY_PATH_STRING
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockByRef
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockByRefDataType
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayout
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.doesPCodeOpPutStackBlockPointerOnStack
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.isAddressBlockLayout
import lol.fairplay.ghidraapple.analysis.utilities.address
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
        if (decompileResults.highFunction == null) {
            Msg.error(this, "Failed to decompile function at ${function.entryPoint}")
            return false
        }

        val pcodeOps =
            decompileResults.highFunction.pcodeOps
                .iterator()
                .asSequence()

        // If we cannot determine the first op, we should bail early.
        val opAtAddress =
            pcodeOps.first { it.seqnum.target == instruction.address }
                ?: return false

        // If the first op does not put a stack block pointer onto the stack, we should bail early.
        if (!doesPCodeOpPutStackBlockPointerOnStack(opAtAddress, program)) return false

        val minimalBlockLayoutType =
            BlockLayoutDataType(
                program.dataTypeManager,
                "${instruction.address}_minimal",
                "${instruction.address}_minimal",
            )

        val minimalBlockLayoutSize = minimalBlockLayoutType.length

        // This will contain the stack block as it would appear on the stack.
        val stackBlockByteArray = ByteArray(minimalBlockLayoutSize)

        val baseStackOffset = opAtAddress.output.address.offset

        function.stackFrame.createVariable(
            "block_minimal_${instruction.address}",
            baseStackOffset.toInt(),
            minimalBlockLayoutType,
            SourceType.ANALYSIS,
        )

        val ops =
            listOf(opAtAddress) +
                opAtAddress.basicIter
                    .asSequence()
                    .filter { it.seqnum.order > opAtAddress.seqnum.order }
                    .filter { it.output?.address?.isStackAddress == true }
                    .sortedBy { it.seqnum.order }
                    .toList()

        for (op in ops) {
            if (op !is PcodeOpAST) continue
            val positiveOffset = op.output.address.offset - baseStackOffset
            // If the offset isn't within the range for our stack block, skip it.
            if (positiveOffset < 0 || positiveOffset >= minimalBlockLayoutSize) continue
            val bytes = op.getOutputBytes(program) ?: continue
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
                baseStackOffset.toInt(),
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

class MarkBlockByRef(
    val function: Function,
    val instruction: Instruction,
) : BackgroundCommand<Program>() {
    constructor(function: Function, address: Address) : this(function, function.program.listing.getInstructionAt(address))

    constructor(program: Program, address: Address) : this(program.listing.getFunctionContaining(address), address)

    override fun getName(): String = "Mark Block Reference Variable at 0x${instruction.address}"

    override fun applyTo(
        program: Program,
        monitor: TaskMonitor,
    ): Boolean {
        // If the address is already marked as a block, don't do it again.
        if (program.isAddressBlockLayout(instruction.address)) return false

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

        val pcodeOps =
            decompileResults.highFunction.pcodeOps
                .iterator()
                .asSequence()

        // If we cannot determine the first op, we should bail early.
        val opAtAddress =
            pcodeOps.first { it.seqnum.target == instruction.address }
                ?: return false

        val minimalBlockByRefType =
            BlockByRefDataType(
                program.dataTypeManager,
                "${instruction.address}_minimal",
            )

        val minimalBlockByRefSize = minimalBlockByRefType.length

        val baseStackOffset = opAtAddress.output.address.offset

        function.stackFrame.createVariable(
            "block_byref_minimal_${instruction.address}",
            baseStackOffset.toInt(),
            minimalBlockByRefType,
            SourceType.ANALYSIS,
        )

        val ops =
            listOf(opAtAddress) +
                opAtAddress.basicIter
                    .asSequence()
                    .filter { it.seqnum.order > opAtAddress.seqnum.order }
                    .filter { it.output?.address?.isStackAddress == true }
                    .sortedBy { it.seqnum.order }
                    .toList()

        fun makeBlockByRefByteArray(byteArraySize: Int): ByteArray {
            // This will contain the block reference variable as it would appear on the stack.
            val byteArray = ByteArray(byteArraySize)

            for (op in ops) {
                if (op !is PcodeOpAST) continue
                val positiveOffset = op.output.address.offset - baseStackOffset
                // If the offset isn't within the range, skip it.
                if (positiveOffset < 0 || positiveOffset >= byteArraySize) continue
                val bytes = op.getOutputBytes(program) ?: continue
                bytes.copyInto(byteArray, positiveOffset.toInt())
            }

            return byteArray
        }

        // Parse the block very minimally (just enough to get the size).
        val minimalBlockByRef =
            BlockByRef(
                program,
                ByteBuffer.wrap(makeBlockByRefByteArray(minimalBlockByRefSize)).order(ByteOrder.LITTLE_ENDIAN),
                instruction.address.toString(),
                minimal = true,
            )

        // Use the actual size for the second and final parsing pass.
        BlockByRef(
            program,
            ByteBuffer.wrap(makeBlockByRefByteArray(minimalBlockByRef.size.toInt())).order(ByteOrder.LITTLE_ENDIAN),
            instruction.address.toString(),
        ).apply {
            // Now that we know we have a good block reference variable type, we mark it up.
            Msg.info(this, "Marking block reference variable at 0x${instruction.address}")
            function.stackFrame.createVariable(
                "block_byref_${instruction.address}",
                baseStackOffset.toInt(),
                toDataType(),
                SourceType.ANALYSIS,
            )
            // We don't need the minimal type now that we have the more complete type. Remove it.
            program.dataTypeManager.apply {
                // Yes, we do need to call [getDataType] and get another instance. Calling [remove] with
                //  the existing instance does not work, unfortunately.
                remove(
                    getDataType(CategoryPath(BLOCK_CATEGORY_PATH_STRING), minimalBlockByRefType.name),
                    TaskMonitor.DUMMY,
                )
            }
        }
        // TODO: Maybe perform a second pass to get better typing for the imported variables.

        return true
    }
}
