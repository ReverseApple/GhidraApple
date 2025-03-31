package lol.fairplay.ghidraapple.analysis.mach.messaging.mig

import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.decompiler.util.FillOutStructureHelper
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.app.util.bin.StructConverter
import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.UnionDataType
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.UndefinedFunction
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.mach.messaging.MachMessageDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.getLabelAtAddress
import lol.fairplay.ghidraapple.analysis.utilities.getPotentiallyUndefinedFunctionAtAddress

private const val MIG_CATEGORY_PATH_STRING = "/GA_MACH/MIG"

class MIGSubsystem(
    private val program: Program,
    reader: BinaryReader,
    private var name: String,
) : StructConverter {
    val serverRoutinePointer =
        reader
            .readNextLong()
            // We try to recover the subsystem name from the server routine function name.
            // https://github.com/apple-oss-distributions/bootstrap_cmds/blob/bootstrap_cmds-136/migcom.tproj/server.c#L609-L612
            .also { serverRoutinePointerValue ->
                program
                    .getLabelAtAddress(program.address(serverRoutinePointerValue))
                    ?.let { serverRoutineFunctionName ->
                        Regex("_([A-z0-9_-]+)_server_routine")
                            .matchEntire(serverRoutineFunctionName)
                            ?.let { match -> name = match.groupValues[1] }
                    }
            }
    val minimumRoutineID = reader.readNextUnsignedInt()
    val maximumRoutineID = reader.readNextUnsignedInt()
    private val routineCount = (maximumRoutineID - minimumRoutineID)
    val maximumMessageSize =
        reader.let {
            val value = it.readNextUnsignedInt()
            // We have to account for the alignment bytes.
            it.pointerIndex += 4
            return@let value
        }
    private val reserved =
        reader
            .readNextLong()
            // For MIG subsystems compiled with the `-t` (`UseRPCTrap`) option, this field will be an actual
            //  pointer. Otherwise, it is 0. `UseRPCTrap` is a non-standard option that we'll probably never
            //  come across in the wild (as even the MIG compiler warns when it is used), but it's better to
            //  be safe than sorry.
            // https://github.com/apple-oss-distributions/bootstrap_cmds/blob/bootstrap_cmds-136/migcom.tproj/server.c#L442-L447
            // https://github.com/apple-oss-distributions/bootstrap_cmds/blob/bootstrap_cmds-136/migcom.tproj/mig.c#L213
            .also {
                if (it != 0L) {
                    throw IllegalStateException("Subsystems compiled with RPC traps are not supported!")
                }
            }
    val routines =
        generateSequence { MIGRoutineDescriptor(reader) }
            .take(routineCount.toUInt().toInt())
            .toList()

    override fun toDataType(): DataType {
        val subsystemCategoryPath =
            CategoryPath(MIG_CATEGORY_PATH_STRING).extend("subsystem_$name")
        val subsystemTypeName = "mig_subsystem_$name"
        return program.dataTypeManager.getDataType(subsystemCategoryPath, subsystemTypeName)
            ?: makeMIGSubsystemDataType(
                program.dataTypeManager,
                subsystemCategoryPath,
                subsystemTypeName,
                routineCount,
            )
    }

    constructor(program: Program, address: Address) : this(
        program,
        BinaryReader(MemoryByteProvider(program.memory, address), !program.memory.isBigEndian),
        address.toString(),
    )

    private fun getRoutineName(routineIndex: Int): String {
        val paddedRoutineIndex =
            routineIndex
                .toString()
                .padStart((routineCount).toString().length, '0')
        return "routine_$paddedRoutineIndex"
    }

    fun markup(renameNonDefaultNamedFunctions: Boolean) {
        val subsystemNamespace =
            program.symbolTable.createNameSpace(null, "mig_subsystem_$name", SourceType.USER_DEFINED)
        routines.forEachIndexed { index, routine ->
            val stubRoutineFunction =
                program
                    .getPotentiallyUndefinedFunctionAtAddress(program.address(routine.stubRoutinePointer)) ?: run {
                    // Return early if the stub routine pointer is NULL.
                    if (routine.stubRoutinePointer == 0L) return@forEachIndexed
                    Msg.info(
                        this,
                        "Failed to find stub routine function for $name routine $index. " +
                            "No function exists at 0x${program.address(routine.stubRoutinePointer)}.",
                    )
                    return@forEachIndexed
                }
            stubRoutineFunction
                .let { originalFunction ->
                    // If this is an [UndefinedFunction], we actually can't give it a namespace
                    //  like we attempt to below. So first we need to make it a real function.
                    if (originalFunction is UndefinedFunction) {
                        CreateFunctionCmd(originalFunction.entryPoint).let {
                            // If the application of the command succeeded, use the newly-created
                            //  function. Otherwise, fallback to the original function.
                            if (it.applyTo(program)) it.function else originalFunction
                        }
                    } else {
                        // If it isn't an [UndefinedFunction], just use it as-is.
                        originalFunction
                    }
                }.let { routineFunction ->
                    if (routineFunction !is UndefinedFunction) routineFunction.parentNamespace = subsystemNamespace
                    run renameFunction@{
                        if (routineFunction.name != "FUN_${routineFunction.entryPoint}" &&
                            !renameNonDefaultNamedFunctions
                        ) {
                            return@renameFunction
                        }
                        routineFunction.setName(getRoutineName(index), SourceType.ANALYSIS)
                    }
                    run updateFunction@{
                        val requestMessageType =
                            MachMessageDataType(
                                program.dataTypeManager,
                                "${getRoutineName(index)}_request",
                            ).apply { categoryPath = toDataType().categoryPath }
                        val successfulReplyMessageType =
                            MachMessageDataType(
                                program.dataTypeManager,
                                "${getRoutineName(index)}_reply_success",
                                size = routine.maxReplyMessageSize.toInt(),
                            ).apply { categoryPath = toDataType().categoryPath }
                        val replyUnionDataType =
                            UnionDataType("${getRoutineName(index)}_reply")
                                .apply {
                                    add(successfulReplyMessageType, -1, "success", null)
                                    add(migReplyErrorDataType, -1, "error", null)
                                }.apply { categoryPath = toDataType().categoryPath }
                        routineFunction.updateFunction(
                            // Keep the same calling convention
                            routineFunction.callingConventionName,
                            // Keep the same return type
                            ReturnParameterImpl(routineFunction.returnType, program),
                            listOf(
                                ParameterImpl("request", PointerDataType(requestMessageType), program),
                                ParameterImpl("reply", PointerDataType(replyUnionDataType), program),
                            ),
                            FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                            true,
                            SourceType.ANALYSIS,
                        )
                    }
                    run fillOutRequestType@{
                        FillOutStructureHelper(program, TaskMonitor.DUMMY).apply {
                            val decompilerInterface = setUpDecompiler(DecompileOptions())
                            val filledOutStructure =
                                processStructure(
                                    computeHighVariable(
                                        routineFunction.parameters
                                            .first()
                                            .variableStorage.minAddress,
                                        routineFunction,
                                        decompilerInterface,
                                    ),
                                    routineFunction,
                                    false,
                                    false,
                                    decompilerInterface,
                                )
                            program.dataTypeManager.addDataType(
                                PointerDataType(filledOutStructure),
                                DataTypeConflictHandler.REPLACE_HANDLER,
                            )
                        }
                    }
                }
        }
    }
}

class MIGRoutineDescriptor(
    reader: BinaryReader,
) {
    val implRoutinePointer = reader.readNextLong()
    val stubRoutinePointer = reader.readNextLong()
    val argumentCount = reader.readNextUnsignedInt()
    val descriptorCount = reader.readNextUnsignedInt()
    val routineArgumentDescriptorPointer = reader.readNextLong()
    val maxReplyMessageSize =
        reader.let {
            val value = it.readNextUnsignedInt()
            // We have to account for the alignment bytes.
            it.pointerIndex += 4
            return@let value
        }
}
