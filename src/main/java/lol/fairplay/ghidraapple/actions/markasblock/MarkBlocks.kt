package lol.fairplay.ghidraapple.actions.markasblock

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.StackReference
import ghidra.util.Msg
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
            // We use the flags to propagate types and such. If we don't have any, something probably went wrong.
            if (flagsBitfield == 0) {
                throw IllegalStateException("No flags recovered from global block at $address!")
                return@apply
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
            // Use the references to build up another copy of the stack.
            iteratedInstruction.referencesFrom.let { references ->
                if (references.isEmpty()) return@let
                val (stackReference, otherReferences) =
                    iteratedInstruction.referencesFrom.toList().let {
                        val stackReference = it.filterIsInstance<StackReference>().firstOrNull()
                        Pair(stackReference, it.filterNot { it == stackReference })
                    }
                // If this instruction doesn't reference the stack, skip it.
                if (stackReference == null) return@let

                val positiveStackOffsetForThisInstruction = stackReference.stackOffset - baseStackOffset
                // If the offset isn't within the range for our stack block, skip it.
                if (
                    positiveStackOffsetForThisInstruction < 0 ||
                    positiveStackOffsetForThisInstruction >= minimalBlockLayoutSize
                ) {
                    return@let
                }

                when {
                    // When we have other references, just put their addresses together as longs and copy them
                    //  into our stack-reference-based stack block.
                    otherReferences.isNotEmpty() ->
                        otherReferences.apply {
                            ByteBuffer
                                .allocate(Long.SIZE_BYTES * size)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .apply { forEach { putLong(it.toAddress.offset) } }
                                .array()
                                .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                        }
                    // If we don't have any other references, we need to confirm if we'll correctly capture the
                    //  bytes being written to the stack.
                    else -> {
                        // Check for a source register.
                        val sourceRegister =
                            iteratedInstruction.getOpObjects(0)[0] as? Register ?: return
                        // If it's a zero register, don't worry about it.
                        if (Register.TYPE_ZERO and sourceRegister.typeFlags != 0) return

                        run find_register_value@{
                            run attempt_without_decompile@{
                                fun matchingLoadsInInstructions(list: List<Instruction>) =
                                    list
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

                                // Look for matching load instructions in the function.
                                val matchingLoads =
                                    matchingLoadsInInstructions(
                                        generateSequence(iteratedInstruction) { it.previous }
                                            .takeWhile { it.address.offset > instructions.first().address.offset }
                                            .toList(),
                                    ).takeIf { it.isNotEmpty() }
                                        ?: matchingLoadsInInstructions(
                                            function.body
                                                .flatMap { it }
                                                .mapNotNull { program.listing.getInstructionAt(it) },
                                        )

                                // If all the loads are the same, we can use any one of them. We'll use the first one.
                                if (matchingLoads.all { it.contentEquals(matchingLoads.first()) }) {
                                    // Copy the load bytes into the stack-reference-based stack block.
                                    matchingLoads
                                        .first()
                                        .copyInto(stackReferenceBlockBytes, positiveStackOffsetForThisInstruction)
                                    // Return early. We found the value.
                                    return@find_register_value
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
                        }
                    }
                }
            }
        }
    }

    // Finally build and markup the stack block.

    BlockLayout(
        program,
        ByteBuffer.wrap(stackReferenceBlockBytes).order(ByteOrder.LITTLE_ENDIAN),
        instruction.address.toString(),
    ).apply {
        // We use the flags to propagate types and such. If we don't have any, something probably went wrong.
        if (flagsBitfield == 0) {
            throw IllegalStateException("No flags recovered from stack block at ${instruction.address}!")
            return@apply
        }
        Msg.info(this, "Marking stack block at 0x${instruction.address}")

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
