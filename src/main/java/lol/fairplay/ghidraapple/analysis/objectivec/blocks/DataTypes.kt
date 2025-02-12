package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.UnsignedLongLongDataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.symbol.StackReference
import ghidra.program.util.ProgramLocation

private const val BLOCK_CATEGORY_PATH_STRING = "/GA_BLOCK"

enum class BlockFlag(
    val value: Int,
) {
    BLOCK_INLINE_LAYOUT_STRING(1 shl 21),
    BLOCK_SMALL_DESCRIPTOR(1 shl 22),
    BLOCK_IS_NOESCAPE(1 shl 23),
    BLOCK_NEEDS_FREE(1 shl 24),
    BLOCK_HAS_COPY_DISPOSE(1 shl 25),
    BLOCK_HAS_CTOR(1 shl 26),
    BLOCK_IS_GC(1 shl 27),
    BLOCK_IS_GLOBAL(1 shl 28),
    BLOCK_USE_STRET(1 shl 29),
    BLOCK_HAS_SIGNATURE(1 shl 30),
    BLOCK_HAS_EXTENDED_LAYOUT(1 shl 31),
}

class BlockLayoutDataType(
    dataTypeManager: DataTypeManager?,
    rootDataTypeSuffix: String?,
    invokeFunctionTypeSuffix: String?,
    invokeReturnType: DataType,
    parameters: Array<ParameterDefinitionImpl>,
    importedVariables: Array<Triple<DataType, String, String?>>,
) : StructureDataType(
        CategoryPath(BLOCK_CATEGORY_PATH_STRING),
        "Block_layout${rootDataTypeSuffix?.let { "_$it" } ?: ""}",
        0,
        dataTypeManager,
    ) {
    companion object {
        fun minimalBlockType(dataTypeManager: DataTypeManager? = null) =
            BlockLayoutDataType(
                dataTypeManager,
                null,
                null,
                VoidDataType.dataType,
                emptyArray(),
                emptyArray(),
            )

        fun isLocationBlockLayout(location: ProgramLocation): Boolean =
            location.program.listing
                .getDataAt(location.address)
                ?.let { isDataTypeBlockLayoutType(it.dataType) } == true ||
                location.program.listing
                    .getFunctionContaining(location.address)
                    .stackFrame.stackVariables
                    .firstOrNull {
                        it.stackOffset ==
                            location.program.listing
                                .getInstructionAt(location.address)
                                .referencesFrom
                                .firstOrNull { it is StackReference }
                                ?.let { (it as StackReference).stackOffset }
                    }?.let { isDataTypeBlockLayoutType(it.dataType) } == true

        fun isDataTypeBlockLayoutType(dataType: DataType) =
            dataType is BlockLayoutDataType ||
                // Most times the class reference is lost. In those cases, we fall back to the name and category path.
                (
                    dataType.name.startsWith(minimalBlockType().name) &&
                        dataType.categoryPath.toString() == BLOCK_CATEGORY_PATH_STRING
                )
    }
    constructor(
        dataTypeManager: DataTypeManager,
        mainTypeSuffix: String?,
        invokeFunctionTypeSuffix: String?,
        invokeReturnType: DataType,
        parameters: Array<ParameterDefinitionImpl>,
        extraBytes: Int,
    ) : this(
        dataTypeManager,
        mainTypeSuffix,
        invokeFunctionTypeSuffix,
        invokeReturnType,
        parameters,
        arrayOf(
            Triple(ArrayDataType(ByteDataType.dataType, extraBytes), "unknown", null),
        ),
    )

    init {
        add(PointerDataType(VoidDataType.dataType, dataTypeManager), "isa", null)
        add(IntegerDataType.dataType, "flags", null)
        add(IntegerDataType.dataType, "reserved", null)
        val invokeFunctionType =
            FunctionDefinitionDataType(
                CategoryPath(BLOCK_CATEGORY_PATH_STRING),
                "invoke${invokeFunctionTypeSuffix?.let { "_$it" } ?: ""}",
            ).apply {
                returnType = invokeReturnType
                arguments =
                    arrayOf(
                        ParameterDefinitionImpl(
                            "block",
                            PointerDataType(
                                // Throwing this all together at once seems to avoid data type conflicts. If this
                                //  were instead defined outside the `apply` block and then used inside, it seems
                                //  to cause two data types to be defined for this singular block layout type.
                                this@BlockLayoutDataType,
                                dataTypeManager,
                            ),
                            null,
                        ),
                    ) + parameters
            }
        add(PointerDataType(invokeFunctionType, dataTypeManager), "invoke", null)
        add(PointerDataType(BlockDescriptor1DataType(dataTypeManager), dataTypeManager), "descriptor", null)
        importedVariables.forEach { (type, name, comment) -> add(type, name, comment) }
    }
}

class BlockDescriptor1DataType(
    dataTypeManager: DataTypeManager?,
) : StructureDataType(CategoryPath(BLOCK_CATEGORY_PATH_STRING), "Block_descriptor_1", 0, dataTypeManager) {
    init {
        add(UnsignedLongLongDataType.dataType, "reserved", null)
        add(UnsignedLongLongDataType.dataType, "size", null)
    }
}

class BlockDescriptor2DataType(
    dataTypeManager: DataTypeManager?,
) : StructureDataType(CategoryPath(BLOCK_CATEGORY_PATH_STRING), "Block_descriptor_2", 0, dataTypeManager) {
    init {
        val copyHelperFunctionDataType =
            FunctionDefinitionDataType("copy_helper").apply {
                returnType = VoidDataType.dataType
                arguments =
                    arrayOf(
                        ParameterDefinitionImpl("dst", PointerDataType(VoidDataType(), dataTypeManager), null),
                        ParameterDefinitionImpl("src", PointerDataType(VoidDataType(), dataTypeManager), null),
                    )
            }
        add(PointerDataType(copyHelperFunctionDataType), "copy_helper", null)
        val disposeHelperFunctionDataType =
            FunctionDefinitionDataType("dispose_helper").apply {
                returnType = VoidDataType.dataType
                arguments =
                    arrayOf(
                        ParameterDefinitionImpl("dst", PointerDataType(VoidDataType(), dataTypeManager), null),
                        ParameterDefinitionImpl("src", PointerDataType(VoidDataType(), dataTypeManager), null),
                    )
            }
        add(PointerDataType(disposeHelperFunctionDataType, dataTypeManager), "dispose_helper", null)
    }
}

class BlockDescriptor3DataType(
    dataTypeManager: DataTypeManager,
) : StructureDataType(CategoryPath(BLOCK_CATEGORY_PATH_STRING), "Block_descriptor_3", 0, dataTypeManager) {
    init {
        add(PointerDataType(CharDataType.dataType, dataTypeManager), "signature", null)
        // TODO: Potentially handle this data type better (it appears to be polymorphic).
        add(PointerDataType(CharDataType.dataType, dataTypeManager), "layout", null)
    }
}
