package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.UnsignedIntegerDataType
import ghidra.program.model.data.UnsignedLongLongDataType
import ghidra.program.model.data.VoidDataType

const val BLOCK_CATEGORY_PATH_STRING = "/GA_BLOCK"

/**
 * A data type representing a block.
 *
 * @param dataTypeManager The data type manager to create the type in the context of.
 * @param rootDataTypeSuffix A suffix for the root data type (this one).
 * @param invokeFunctionTypeSuffix A suffix for the function type used for the "invoke" component.
 * @param invokeReturnType The return type to use for the "invoke" function type.
 * @param parameters The parameters to use for the "invoke" function type.
 * @param capturedVariables The captured variables from outside the scope of the block.
 */
class BlockLayoutDataType(
    dataTypeManager: DataTypeManager? = null,
    rootDataTypeSuffix: String? = null,
    invokeFunctionTypeSuffix: String? = null,
    invokeReturnType: DataType = VoidDataType.dataType,
    parameters: Array<ParameterDefinitionImpl> = emptyArray(),
    capturedVariables: Array<Triple<DataType, String, String?>> = emptyArray(),
) : StructureDataType(
        CategoryPath(BLOCK_CATEGORY_PATH_STRING),
        "Block_layout${rootDataTypeSuffix?.let { "_$it" } ?: ""}",
        0,
        dataTypeManager,
    ) {
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
                setArguments(
                    *
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
                        ) + parameters,
                )
            }
        add(PointerDataType(invokeFunctionType, dataTypeManager), "invoke", null)
        add(PointerDataType(BlockDescriptor1DataType(dataTypeManager), dataTypeManager), "descriptor", null)
        capturedVariables.forEach { (type, name, comment) -> add(type, name, comment) }
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
                setArguments(
                    *arrayOf(
                        ParameterDefinitionImpl("dst", PointerDataType(VoidDataType(), dataTypeManager), null),
                        ParameterDefinitionImpl("src", PointerDataType(VoidDataType(), dataTypeManager), null),
                    ),
                )
            }
        add(PointerDataType(copyHelperFunctionDataType), "copy_helper", null)
        val disposeHelperFunctionDataType =
            FunctionDefinitionDataType("dispose_helper").apply {
                returnType = VoidDataType.dataType
                setArguments(
                    *arrayOf(
                        ParameterDefinitionImpl("dst", PointerDataType(VoidDataType(), dataTypeManager), null),
                        ParameterDefinitionImpl("src", PointerDataType(VoidDataType(), dataTypeManager), null),
                    ),
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

class BlockByRefDataType(
    dataTypeManager: DataTypeManager,
    dataTypeSuffix: String? = null,
    expectedSize: UInt? = null,
    hasBlockByRef2: Boolean = false,
    hasBlockByRef3: Boolean = false,
) : StructureDataType(
        CategoryPath(BLOCK_CATEGORY_PATH_STRING),
        "Block_byref${dataTypeSuffix?.let { "_$it" } ?: ""}",
        0,
        dataTypeManager,
    ) {
    init {
        add(PointerDataType(VoidDataType.dataType, dataTypeManager), "isa", null)
        add(PointerDataType(this, dataTypeManager), "forwarding", null)
        add(IntegerDataType.dataType, "flags", null)
        add(UnsignedIntegerDataType.dataType, "size", null)
        if (hasBlockByRef2) add(BlockByRef2DataType(dataTypeManager), "byref2", null)
        if (hasBlockByRef3) add(BlockByRef3DataType(dataTypeManager), "byref3", null)
        expectedSize?.let {
            val remainingBytes = it.toInt() - this.length
            if (remainingBytes > 0) {
                repeat(remainingBytes) { add(DEFAULT) }
            }
            // TODO: Maybe handle the case where [remainingBytes] < 0
        }
    }
}

class BlockByrefKeepFunctionDefinitionDataType(
    dataTypeManager: DataTypeManager,
) : FunctionDefinitionDataType("BlockByrefKeepFunction", dataTypeManager) {
    init {
        val blockByRefPointerType =
            PointerDataType(BlockByRef3DataType(dataTypeManager), dataTypeManager)
        setArguments(
            *arrayOf(
                ParameterDefinitionImpl(null, blockByRefPointerType, null),
                ParameterDefinitionImpl(null, blockByRefPointerType, null),
            ),
        )
    }
}

class BlockByrefDestroyFunctionDefinitionDataType(
    dataTypeManager: DataTypeManager,
) : FunctionDefinitionDataType("BlockByrefDestroyFunction", dataTypeManager) {
    init {
        setArguments(
            *arrayOf(
                ParameterDefinitionImpl(
                    null,
                    PointerDataType(BlockByRef3DataType(dataTypeManager), dataTypeManager),
                    null,
                ),
            ),
        )
    }
}

class BlockByRef2DataType(
    dataTypeManager: DataTypeManager,
) : StructureDataType(
        CategoryPath(BLOCK_CATEGORY_PATH_STRING),
        "Block_byref_2",
        0,
        dataTypeManager,
    ) {
    init {
        add(PointerDataType(BlockByrefKeepFunctionDefinitionDataType(dataTypeManager)), "byref_keep", null)
        add(PointerDataType(BlockByrefDestroyFunctionDefinitionDataType(dataTypeManager)), "byref_destroy", null)
    }
}

class BlockByRef3DataType(
    dataTypeManager: DataTypeManager,
    dataTypeSuffix: String? = null,
) : StructureDataType(
        CategoryPath(BLOCK_CATEGORY_PATH_STRING),
        "Block_byref_3",
        0,
        dataTypeManager,
    ) {
    init {
        // TODO: Potentially handle this data type better (it appears to be polymorphic).
        add(PointerDataType(CharDataType.dataType, dataTypeManager), "layout", null)
    }
}
