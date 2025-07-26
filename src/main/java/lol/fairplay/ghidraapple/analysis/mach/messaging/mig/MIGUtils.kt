package lol.fairplay.ghidraapple.analysis.mach.messaging.mig

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.data.Array
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.mach.messaging.macOSXDataTypeManager
import lol.fairplay.ghidraapple.analysis.utilities.instructions
import kotlin.also
import kotlin.let

val migSubsystemDataType = macOSXDataTypeManager.getDataType("/mig.h/mig_subsystem")!!
val migReplyErrorDataType = macOSXDataTypeManager.getDataType("/mig_errors.h/mig_reply_error_t")!!

/**
 * Determines if a function is a MIG server routine.
 *
 * MIG server routine functions are compiled to C using a
 * [very simple process](https://github.com/apple-oss-distributions/bootstrap_cmds/blob/bootstrap_cmds-136/migcom.tproj/server.c#L612-L634),
 * leading to fairly-consistent PCode across all cases. We can use that to our advantage when detecting such functions.
 */
fun isFunctionMIGServerRoutine(function: Function): Boolean {
    // If there are a good number of instructions, this function
    //  is likely too complex to be a MIG server routine.
    if (function.instructions.size > 40) return false

    // A MIG server routine will attempt to access the message ID from the first argument. Since this
    //  will be one of the first things to happen in the function, and since the message ID will live
    //  at 0x14 in the first argument, we can heuristically check for a matching instruction.
    fun isInstructionAccessingMessageIDField(instruction: Instruction): Boolean {
        if (instruction.pcode.size != 3) return false
        if (instruction.pcode[0].opcode != PcodeOp.INT_ADD) return false
        if (!instruction.pcode[0].inputs.any { it.isConstant && it.offset == 0x14L }) return false
        if (instruction.pcode[1].opcode != PcodeOp.LOAD) return false
        if (instruction.pcode[2].opcode != PcodeOp.INT_ZEXT) return false
        return true
    }
    // For [UndefinedFunctions] the [instructions] might be empty, so to
    //  cover all cases, we manually iterate from the beginning.
    if (!generateSequence(function.program.listing.getInstructionAt(function.entryPoint)) { it.next }
            // The instruction to access the message ID field should be one of the first several.
            .take(15)
            .any(::isInstructionAccessingMessageIDField)
    ) {
        return false
    }

    // We're now pretty sure that this is a MIG server routine, but we need to decompile
    //  it to be sure. Hopefully the above checks weeded out any functions that would be
    //  slow to decompile. An actual MIG server routine should decompile very quickly.

    val pcodeOps =
        DecompInterface()
            .let { decompiler ->
                decompiler.simplificationStyle = "normalize"
                decompiler.openProgram(function.program)
                decompiler
                    .decompileFunction(function, 3, TaskMonitor.DUMMY)
                    .also { decompiler.dispose() }
            }.highFunction.pcodeOps
            .iterator()
            .asSequence()
            .toList()

    val rangeCheckPCodeOps =
        arrayOf(
            PcodeOp.INT_ADD,
            PcodeOp.LOAD,
            PcodeOp.INT_ADD,
            PcodeOp.INT_LESS,
            PcodeOp.CBRANCH,
            PcodeOp.COPY,
        )

    val routineDemuxPCodeOps =
        arrayOf(
            PcodeOp.INT_ZEXT,
            PcodeOp.INT_MULT,
            PcodeOp.INT_ADD,
            PcodeOp.LOAD,
        )

    fun doesPCodeOpsContainServerRoutineLogicAtIndex(index: Int): Boolean {
        // We need to set aside the index in a variable so we can mutate it.
        var searchIndex = index
        // A server routine will first check of the incoming ID is in the expected range, and
        //  returns early if it is not. We'll check for that logic here.
        rangeCheckPCodeOps.forEach { rangeCheckOpCode ->
            if (searchIndex > pcodeOps.lastIndex) return false
            if (pcodeOps[searchIndex].opcode != rangeCheckOpCode) return false
            searchIndex++
        }
        // If the server routine function was compiled with stack-checking, there will likely be
        //  a branch here to the stack-checking instructions at the end of the function, instead
        //  of a simple return instruction. We need to account for both cases.
        if (!arrayOf(PcodeOp.RETURN, PcodeOp.BRANCH).contains(pcodeOps[searchIndex].opcode)) {
            return false
        }
        searchIndex++
        // Sometimes there's an INT_ADD instruction, sometimes there's not.
        if (pcodeOps[searchIndex].opcode == PcodeOp.INT_ADD) searchIndex++
        // Once the incoming ID has been range-checked, a server routine will use the ID to index
        //  into the routine array and load a pointer to it. We'll check that logic here.
        routineDemuxPCodeOps.forEachIndexed { index, rangeCheckOpCode ->
            if (searchIndex > pcodeOps.lastIndex) return false
            if (pcodeOps[searchIndex].opcode != rangeCheckOpCode) return false
            searchIndex++
        }
        return true
    }

    // We check if the server routine logic exists at any PCode index, because the function may be
    //  prefixed with instructions related to stack-checking. We want to ignore those operations.
    return pcodeOps.indices.any(::doesPCodeOpsContainServerRoutineLogicAtIndex)
}

fun makeMIGSubsystemDataType(
    dataTypeManager: DataTypeManager,
    categoryPath: CategoryPath,
    name: String,
    routineCount: Long,
): DataType {
    if (routineCount > Int.MAX_VALUE) {
        throw IllegalArgumentException("Routine count is too large! $routineCount > ${Int.MAX_VALUE}")
    }
    return migSubsystemDataType.let { original ->
        (original.copy(dataTypeManager) as Structure).let { copy ->
            copy.name = name
            copy.categoryPath = categoryPath
            (original as Structure)
                .components
                .first { it.fieldName == "routine" }
                // We need to delete the original routine array and recreate one with the proper size.
                .let { originalRoutineArrayComponent ->
                    copy.clearComponent(originalRoutineArrayComponent.ordinal)
                    val originalRoutineArrayElementType =
                        (originalRoutineArrayComponent.dataType as Array).dataType
                    copy.add(
                        ArrayDataType(originalRoutineArrayElementType, routineCount.toUInt().toInt()),
                        originalRoutineArrayComponent.fieldName,
                        originalRoutineArrayComponent.comment,
                    )
                }
            return@let copy
        }
    }
}
