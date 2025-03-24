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
    // If there are more than 20 instructions, this function
    //  is too complex to be a MIG server routine.
    if (function.instructions.size > 20) return false

    // A MIG server routine will attempt to access the message ID from the first argument. Since this
    //  will be one of the first things to happen in the function, and since the message ID will live
    //  at 0x14 in the first argument, we can heuristically check for a matching instruction.
    fun Instruction.isAccessingMessageIDField(): Boolean {
        if (pcode.size != 3) return false
        if (pcode[0].opcode != PcodeOp.INT_ADD) return false
        if (pcode[0].inputs.any { it.isConstant && it.offset == 0x14L } != true) return false
        if (pcode[1].opcode != PcodeOp.LOAD) return false
        if (pcode[2].opcode != PcodeOp.INT_ZEXT) return false
        return true
    }
    // For [UndefinedFunctions] the [instructions] might be empty, so to
    //  cover all cases, we manually iterate from the beginning.
    if (generateSequence(function.program.listing.getInstructionAt(function.entryPoint)) { it.next }
            // The instruction to access the message ID field should be one of the first several.
            .take(7)
            .any { it.isAccessingMessageIDField() } != true
    ) {
        return false
    }

    // We're now pretty sure that this is a MIG server routine, but we need to decompile
    //  it to be sure. Hopefully the above checks weeded out any functions that would be
    //  slow to decompile. An actual MIG server routine should decompile very quickly.

    var pcodeOps =
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
    if (pcodeOps.size != 13) return false
    val expectedPCodeOpCodes =
        arrayOf(
            PcodeOp.INT_ADD,
            PcodeOp.LOAD,
            PcodeOp.INT_ADD,
            PcodeOp.INT_LESS,
            PcodeOp.CBRANCH,
            PcodeOp.COPY,
            PcodeOp.RETURN,
            PcodeOp.INT_ADD,
            PcodeOp.INT_ZEXT,
            PcodeOp.INT_MULT,
            PcodeOp.INT_ADD,
            PcodeOp.LOAD,
            PcodeOp.RETURN,
        )
    assert(expectedPCodeOpCodes.size == pcodeOps.size)
    // TODO: Is this enough of a heuristic, or do we need to do more? What are the chances that a
    //  non-MIG-server-routine function would have the same thirteen PCode operations, all in the
    //  same exact order as an actual MIG server routine (and pass all previous checks)?
    for ((index, op) in pcodeOps.withIndex()) {
        if (op.opcode != expectedPCodeOpCodes[index]) return false
    }
    return true
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
