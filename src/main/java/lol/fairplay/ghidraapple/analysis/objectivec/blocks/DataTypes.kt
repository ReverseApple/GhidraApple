package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.program.model.address.Address
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
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.StackReference
import ghidra.program.util.ProgramLocation

private const val BLOCK_CATEGORY_PATH_STRING = "/GA_BLOCK"

/**
 * A data type representing a block.
 *
 * @param dataTypeManager The data type manager to create the type in the context of.
 * @param rootDataTypeSuffix A suffix for the root data type (this one).
 * @param invokeFunctionTypeSuffix A suffix for the function type used for the "invoke" component.
 * @param invokeReturnType The return type to use for the "invoke" function type.
 * @param parameters The parameters to use for the "invoke" function type.
 * @param importedVariables The captured variables from outside the scope of the block.
 */
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

        fun isAddressBlockLayout(
            program: Program,
            address: Address,
        ) = program.listing
            .getDataAt(address)
            ?.let { isDataTypeBlockLayoutType(it.dataType) } == true ||
            program.listing
                .getFunctionContaining(address)
                ?.stackFrame
                ?.stackVariables
                ?.firstOrNull {
                    it.stackOffset ==
                        program.listing
                            .getInstructionAt(address)
                            .referencesFrom
                            .firstOrNull { it is StackReference }
                            ?.let { (it as StackReference).stackOffset }
                }?.let { isDataTypeBlockLayoutType(it.dataType) } == true

        fun isLocationBlockLayout(location: ProgramLocation) = isAddressBlockLayout(location.program, location.address)

        fun isDataTypeBlockLayoutType(dataType: DataType) =
            dataType is BlockLayoutDataType ||
                // Most times the class reference is lost. In those cases, we fall back to the name and category path.
                (
                    dataType.name.startsWith(minimalBlockType().name) &&
                        dataType.categoryPath.toString() == BLOCK_CATEGORY_PATH_STRING
                )
    }

    /**
     * A data type representing a block with a given amount of bytes of imported variables.
     *
     * @param extraBytes The length of the imported variables, in bytes.
     * @see [lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType]
     */
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
        // We don't know what the imported variables are, but at least we know how long they are. For now,
        //  we'll just put in a byte array and allow the user to re-type the struct as necessary.
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
