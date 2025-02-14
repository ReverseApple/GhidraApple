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
                        // If we cannot use the other references, we'll need to confirm if we'll be able to capture
                        //  the values that will be written to the stack.
                        if (isEmpty()) {
                            // Check for a source register.
                            val sourceRegister =
                                iteratedInstruction.getOpObjects(0)[0] as? Register ?: return@apply
                            // If it's a zero register, don't worry about it, it will be zero in the emulator too.
                            if (Register.TYPE_ZERO and sourceRegister.typeFlags != 0) return@apply
                            // Read the value of the register in the emulator.
                            val emulatedValue = helper.readRegister(sourceRegister)
                            // If the emulator has a value, skip this and trust it.
                            if (emulatedValue.longValueExact() != 0L) return@apply

                            // If we're here, the emulator has a zero value. While that might be the value we want to
                            //  write, it may very likely not be. Let's look for a value for the register.

                            run attempt_without_decompile@{
                                // Look for matching load instructions in the function.
                                val matchingLoads =
                                    function.body
                                        .flatMap { it }
                                        .mapNotNull { program.listing.getInstructionAt(it) }
                                        .filter {
                                            // It should have one register result and that register's name should
                                            //  match that of the register we're possibly missing a value from.
                                            it.resultObjects.filterIsInstance<Register>().let {
                                                it.size == 1 && it.first().name == sourceRegister.name
                                            } &&
                                                // It should also have some parsed references we can use to read
                                                //  potential values from memory.
                                                it.referencesFrom.isNotEmpty()
                                        }.mapNotNull {
                                            it.referencesFrom
                                                // Look for READ references.
                                                .firstOrNull { it.referenceType == RefType.READ }
                                                ?.let {
                                                    // Read the bytes from program memory.
                                                    val registerBytes = ByteArray(sourceRegister.numBytes)
                                                    val readBytes =
                                                        program.memory.getBytes(it.toAddress, registerBytes)
                                                    if (readBytes != registerBytes.size) return@let null
                                                    return@let registerBytes
                                                }
                                        }

                                // If all the loads are the same, we can use any one of them. We'll use the first one.
                                if (matchingLoads.all { it.contentEquals(matchingLoads.first()) }) {
                                    // Copy the load bytes into the stack-reference-based stack block.
                                    matchingLoads
                                        .first()
                                        .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                                    // Return early. We found the value.
                                    return@apply
                                }
                                // If some of the loads were different, we can't be sure. Don't do anything and
                                //  instead fallthrough to the next attempt.
                            }

                            // Our attempts to find the register value without using the decompiler failed. We need
                            //  to use the decompiler now :(

                            run attempt_with_decompile@{
                                // Decompile the function.
                                val results =
                                    DecompInterface().let { decompiler ->
                                        decompiler.openProgram(program)
                                        decompiler
                                            .decompileFunction(function, 30, null)
                                            .also { decompiler.dispose() }
                                    }

                                // Find the PCode operation that's associated with the currently iterated instruction.
                                val targetOps =
                                    results.highFunction.pcodeOps
                                        .iterator()
                                        .asSequence()
                                        .filter { it.seqnum.target == iteratedInstruction.address }
                                        .toList()

                                // Find the source [Varnode] for the register.
                                val source =
                                    targetOps
                                        // We need only one operation to have matched.
                                        .singleOrNull()
                                        ?.inputs
                                        // We need an operation with only one input.
                                        ?.singleOrNull()
                                        ?.def
                                        ?.inputs
                                        // We need a defining operation with only one input.
                                        ?.singleOrNull() ?: return@attempt_with_decompile

                                // Read the source bytes from memory. If the source [Varnode] is not in program
                                //  memory, this may fail (but so far it has always been in program memory).
                                val sourceBytes = ByteArray(source.size)
                                val bytesRead = program.memory.getBytes(source.address, sourceBytes)
                                if (bytesRead != sourceBytes.size) return@attempt_with_decompile
                                // Copy the source bytes into the stack-reference-based stack block.
                                sourceBytes
                                    .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                            }
                        } else {
                            // Otherwise, if we have other references, it's far more simple.
                            ByteBuffer
                                .allocate(Long.SIZE_BYTES * otherReferences.size)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .apply { forEach { putLong(it.toAddress.offset) } }
                                .array()
                                .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                        }
                    }
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

    // Ensure our stack-reference-based stack block and emulated stack block are the same size.
    assert(stackReferenceBlockBytes.size == emulatedStackBlockBytes.size)

    // Put them into byte buffers.
    val stackReferenceStackBlockBuffer =
        ByteBuffer.wrap(stackReferenceBlockBytes).order(ByteOrder.LITTLE_ENDIAN)
    val emulatedStackBlockBuffer =
        ByteBuffer.wrap(emulatedStackBlockBytes).order(ByteOrder.LITTLE_ENDIAN)

    // Loop over them, putting non-zero long-sized chunks into the result buffer. In many cases, neither stack
    //  will have the full picture of the actual stack state, so we merge them together to get a more accurate
    //  stack state to pass into the [StructConverter].

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
