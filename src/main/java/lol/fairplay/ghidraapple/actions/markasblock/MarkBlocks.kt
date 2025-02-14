package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.decompiler.DecompInterface
import ghidra.app.emulator.EmulatorHelper
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.RefType
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
            program.withTransaction<Exception>("Mark Global Block at 0x$address") {
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
    val baseStackOffset =
        instruction.referencesFrom
            .filterIsInstance<StackReference>()
            .first()
            .stackOffset

    val minimalBlockLayoutSize =
        BlockLayoutDataType.minimalBlockType(program.dataTypeManager).length

    val stackReferenceBlockBytes = ByteArray(minimalBlockLayoutSize)

    run instruction_loop@{
        instructions.forEach { iteratedInstruction ->
            helper.emulator.setExecuteAddress(iteratedInstruction.address.offset)
            try {
                helper.emulator.executeInstruction(false, null)
            } catch (_: Exception) {
                // Silently fail if the emulator couldn't execute the instruction. It hopefully
                //  wasn't important enough to where we would break things by skipping it.
            }
            // Use the references to build up another copy of the stack.
            iteratedInstruction.referencesFrom.let { references ->
                if (references.isEmpty()) return@let
                val (stackReference, otherReferences) =
                    iteratedInstruction.referencesFrom.toList().let {
                        val stackReference = it.filterIsInstance<StackReference>().firstOrNull()
                        Pair(stackReference, it.filterNot { it == stackReference })
                    }
                if (stackReference != null) {
                    val positiveStackOffsetForThisInstruction = stackReference.stackOffset - baseStackOffset
                    // If the offset isn't within the range for our stack block, skip it.
                    if (
                        positiveStackOffsetForThisInstruction < 0 ||
                        positiveStackOffsetForThisInstruction >= minimalBlockLayoutSize
                    ) {
                        return@let
                    }
                    otherReferences.apply {
                        if (isEmpty()) {
                            // If there are no other references, check for a source register.
                            val sourceRegister = iteratedInstruction.getOpObjects(0)[0] as? Register ?: return@apply
                            // If it's a zero register, don't worry about it, those will be zero in the emulator too.
                            if (Register.TYPE_ZERO and sourceRegister.typeFlags != 0) return@apply
                            // Read the value of the register in the emulator.
                            val emulatedValue = helper.readRegister(sourceRegister)
                            // If the emulator has a value, skip this and trust it.
                            if (emulatedValue.longValueExact() != 0L) return@apply

                            // If we're here, the emulator has a zero value. Let's check for a potential load.

                            run attempt_without_decompile@{
                                val matchingLoads =
                                    function.body
                                        .flatMap { it }
                                        .mapNotNull { program.listing.getInstructionAt(it) }
                                        .filter {
                                            it.resultObjects.filterIsInstance<Register>().let {
                                                it.size == 1 && it.first().name == sourceRegister.name
                                            } &&
                                                it.referencesFrom.isNotEmpty()
                                        }.mapNotNull {
                                            it.referencesFrom
                                                .firstOrNull { it.referenceType == RefType.READ }
                                                ?.let {
                                                    val registerBytes = ByteArray(sourceRegister.numBytes)
                                                    val readBytes =
                                                        program.memory.getBytes(it.toAddress, registerBytes)
                                                    if (readBytes != registerBytes.size) return@let null
                                                    return@let registerBytes
                                                }
                                        }
                                // If all the loads are the same, we can use any one of them. We'll use the first one.
                                if (matchingLoads.all { it.contentEquals(matchingLoads.first()) }) {
                                    matchingLoads
                                        .first()
                                        .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                                    return@apply
                                }
                                // If some of the loads were different, we can't be sure. Don't do anything.
                                return@attempt_without_decompile
                            }

                            run attempt_with_decompile@{
                                val results =
                                    DecompInterface().let { decompiler ->
                                        decompiler.openProgram(program)
                                        decompiler
                                            .decompileFunction(function, 30, null)
                                            .also { decompiler.dispose() }
                                    }

                                val targetOps =
                                    results.highFunction.pcodeOps
                                        .iterator()
                                        .asSequence()
                                        .filter { it.seqnum.target == iteratedInstruction.address }
                                        .toList()

                                val source =
                                    targetOps
                                        .singleOrNull()
                                        ?.inputs
                                        ?.singleOrNull()
                                        ?.def
                                        ?.inputs
                                        ?.singleOrNull() ?: return@attempt_with_decompile
                                val sourceBytes = ByteArray(source.size)
                                val bytesRead = program.memory.getBytes(source.address, sourceBytes)
                                if (bytesRead != sourceBytes.size) return@attempt_with_decompile
                                sourceBytes
                                    .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                            }
                        } else {
                            ByteBuffer
                                .allocate(Long.SIZE_BYTES * otherReferences.size)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .apply { forEach { putLong(it.toAddress.offset) } }
                                .array()
                                .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                        }
                    }
                } else {
                    // TODO: Do we need to do anything here?
                }
            }
        }
    }

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
    ).let {
        if (it.flagsBitfield != 0) return@let it
        // TODO: Handle case where flags are empty.
        return@let it
    }.apply {
        program.withTransaction<Exception>("Mark Stack Block at 0x${instruction.address}") {
            function.stackFrame.createVariable(
                "block_${program.address(invokePointer)}",
                baseStackOffset,
                toDataType(),
                SourceType.ANALYSIS,
            )
            updateProgram()
        }
    }
    // TODO: Maybe perform a second pass to get better typing for the imported variables.
}
