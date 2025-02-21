package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.util.bin.StructConverter
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignatureType
import lol.fairplay.ghidraapple.core.objc.encodings.parseSignature
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

// TODO: Handle stack blocks, verify flags, etc.

// Class property initializations are **guaranteed** by spec to be invoked in the order they appear in the class body.
// https://github.com/Kotlin/kotlin-spec/blob/release/docs/src/md/kotlin.core/declarations.md?plain=1#L881

/**
 * A flag for a block layout.
 */
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

/**
 * An Objective-C block (relevant to the given program) with the layout representation contained in the given buffer.
 *
 * @param program The program the block is in.
 * @param buffer A [ByteBuffer] containing the bytes of the `Block_layout` for the block.
 * @param dataTypeSuffix A suffix for the derived data type.
 */
class BlockLayout(
    private val program: Program,
    buffer: ByteBuffer,
    private val dataTypeSuffix: String? = null,
) : StructConverter {
    val isaPointer = buffer.getLong()
    val flagsBitfield = buffer.getInt()
    val flags: Set<BlockFlag> get() =
        BlockFlag.entries
            .filter { (flagsBitfield and it.value) != 0 }
            .toSet()
    val reserved = buffer.getInt()
    val invokePointer = buffer.getLong()
    val descriptorPointer = buffer.getLong()

    // A block has a descriptor, starting with, at the very least, a `Block_descriptor_1` struct. This is
    //  then followed by (optionally) a `Block_descriptor_2` struct and/or a `Block_descriptor_3` struct,
    //  with whatever structs are included being laid out in memory in ascending numerical order.

    private val descriptorHasCopyDispose get() = BlockFlag.BLOCK_HAS_COPY_DISPOSE in flags
    private val descriptorHasSignature get() = BlockFlag.BLOCK_HAS_SIGNATURE in flags

    private val descriptor1Address = program.address(descriptorPointer)
    private val descriptor2Address get() =
        if (descriptorHasCopyDispose) {
            program
                .address(descriptorPointer)
                .add(BlockDescriptor1DataType(program.dataTypeManager).length.toLong())
        } else {
            null
        }
    private val descriptor3Address get() =
        if (descriptorHasSignature) {
            program
                .address(descriptorPointer)
                .let {
                    if (descriptorHasCopyDispose) {
                        it.add(BlockDescriptor2DataType(program.dataTypeManager).length.toLong())
                    } else {
                        it
                    }
                }.add(BlockDescriptor1DataType(program.dataTypeManager).length.toLong())
        } else {
            null
        }

    /**
     * Reads the bytes of a descriptor part and returns a typed instance [T] representing the data.
     *
     * @param address The base address of the descriptor part.
     * @param byteCount The size, in bytes, of the descriptor part.
     * @param byteBufferToPart An initialization function that turns a [ByteBuffer] into a typed instance [T].
     */
    private inline fun <T : BlockDescriptorPart> readDescriptorPart(
        address: Address,
        byteCount: Int,
        byteBufferToPart: (ByteBuffer) -> T,
    ): T {
        val bytes = ByteArray(byteCount)
        val bytesRead = program.memory.getBytes(address, bytes)
        if (bytesRead != byteCount) throw IOException("Unable to read the required $byteCount bytes.")
        return byteBufferToPart(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN))
    }

    val descriptor1: BlockDescriptor1 get() =
        readDescriptorPart(
            descriptor1Address,
            BlockDescriptor1DataType(program.dataTypeManager).length,
        ) { BlockDescriptor1(program, it) }

    val descriptor2: BlockDescriptor2? get() =
        descriptor2Address?.let {
            readDescriptorPart(
                it,
                BlockDescriptor2DataType(program.dataTypeManager).length,
            ) { BlockDescriptor2(program, it) }
        }

    val descriptor3: BlockDescriptor3? get() =
        descriptor3Address?.let {
            readDescriptorPart(
                it,
                BlockDescriptor3DataType(program.dataTypeManager).length,
            ) { BlockDescriptor3(program, it) }
        }

    val encodedSignature: EncodedSignature? get() = descriptor3?.encodedSignature

    /**
     * Generates data types from the encoded signature.
     */
    fun generateDataTypesFromEncodedSignature(): Pair<DataType, Array<ParameterDefinitionImpl>> {
        encodedSignature?.let {
            val typeResolver = TypeResolver(program)
            val returnType =
                typeResolver.buildParsed(it.returnType.first) ?: {
                    // We don't fail here because the return value is not memory-critical.
                    Msg.debug(
                        this,
                        "Failed to resolve return type for block with descriptor address $descriptor1Address.",
                    )
                    VoidDataType.dataType
                }()
            val parameters =
                it.parameters
                    .mapIndexed { index, (typeNode) ->
                        val oneBasedIndex = index + 1
                        val parameterType =
                            typeResolver.buildParsed(typeNode)
                                ?: throw IOException(
                                    "Failed to parse the type for parameter $oneBasedIndex " +
                                        "for block with descriptor address $descriptor1Address.",
                                )
                        return@mapIndexed ParameterDefinitionImpl("parameter_$oneBasedIndex", parameterType, null)
                    }.toTypedArray()
            return Pair(returnType, parameters)
        } ?: return Pair(VoidDataType.dataType, emptyArray())
    }

    /**
     * Marks up the block's descriptor in the program.
     */
    private fun markupDescriptorParts() {
        DataUtilities.createData(
            program,
            descriptor1Address,
            this.descriptor1.toDataType(),
            -1,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
        )
        descriptor2?.let {
            if (descriptor2Address == null) return
            DataUtilities.createData(
                program,
                descriptor2Address,
                it.toDataType(),
                -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
        }
        descriptor3?.let {
            if (descriptor3Address == null) return
            DataUtilities.createData(
                program,
                descriptor3Address,
                it.toDataType(),
                -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
        }
    }

    /**
     * Updates the pointed-to invoke function to match the encoded block signature.
     */
    private fun updateInvokeFunction() {
        // Return early if there is no signature. We can't trust the data type when that is the case.
        if (!descriptorHasSignature) return
        // We "steal" the invoke function definition from the data type.
        val invokeFunctionType =
            (
                (this.toDataType() as? StructureDataType)
                    ?.components
                    ?.firstOrNull { it.fieldName == "invoke" }
                    ?.dataType as? PointerDataType
            )?.dataType as? FunctionDefinitionDataType ?: return
        val invokeAddress = program.address(invokePointer)
        program.listing
            .getFunctionAt(invokeAddress)
            .let {
                it
                    // In some rare cases, Ghidra may have failed to understand that there is a function at
                    //  the invoke address. We'll clear what's there, disassemble the bytes, and attempt to
                    //  create a new function. This will probably only work fully if there is only a single
                    //  mistaken code unit at the invoke address. The disassembly may not be fully accurate
                    //  if there are additional code units in the way that are not cleared.
                    // TODO: Is there a way that we can **safely** clear more than just the invoke address?
                    ?: run {
                        // Clear what is at the invoke address.
                        program.listing.clearCodeUnits(invokeAddress, invokeAddress, true)
                        // Disassemble, starting from the invoke address.
                        DisassembleCommand(invokeAddress, null, true).applyTo(program)
                        // Create a new function at the address.
                        program.listing.createFunction(
                            "FUN_$invokeAddress",
                            invokeAddress,
                            AddressSet(invokeAddress),
                            SourceType.ANALYSIS,
                        )
                    }
            }.let {
                it.updateFunction(
                    // Keep the same calling convention
                    it.callingConventionName,
                    ReturnParameterImpl(invokeFunctionType.returnType, program),
                    invokeFunctionType.arguments.map { ParameterImpl(it.name, it.dataType, program) },
                    // TODO: Determine if this is the best [FunctionUpdateType] to use here.
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    false,
                    SourceType.DEFAULT,
                )
                // TODO: Determine if [addLocalVariable] will be of any use here for stack blocks.
            }
    }

    /**
     * Marks up the program with the derived data types and updates the invoke function.
     */
    fun markupAdditionalTypes() {
        markupDescriptorParts()
        updateInvokeFunction()
    }

    /**
     * An in-memory block that lives at the given address in the given program.
     */
    constructor(program: Program, address: Address) : this(
        program,
        {
            val minimalBlockType = BlockLayoutDataType.minimalBlockType(program.dataTypeManager)
            val blockBytes = ByteArray(minimalBlockType.length)
            val bytesRead = program.memory.getBytes(address, blockBytes)
            if (bytesRead != blockBytes.size) {
                throw IOException("Unable to read the ${blockBytes.size} needed to parse a global block.")
            }
            ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN)
        }(),
        address.toString(),
    )

    override fun toDataType(): DataType {
        val (blockReturnType, blockParameters) =
            if (program.currentTransactionInfo != null) {
                generateDataTypesFromEncodedSignature()
            } else {
                Pair(VoidDataType.dataType, emptyArray())
            }
        val minimalBlockSize = BlockLayoutDataType.minimalBlockType(program.dataTypeManager).length
        val actualBlockSize = descriptor1.blockSize
        return BlockLayoutDataType(
            program.dataTypeManager,
            dataTypeSuffix,
            program.address(invokePointer).toString(),
            blockReturnType,
            blockParameters,
            extraBytes = (actualBlockSize - minimalBlockSize).toInt(),
        )
    }
}

abstract class BlockDescriptorPart : StructConverter

/**
 * The first part of a block descriptor in the given program.
 */
class BlockDescriptor1(
    private var program: Program,
    buffer: ByteBuffer,
) : BlockDescriptorPart() {
    val reserved = buffer.getLong()
    val blockSize = buffer.getLong()

    override fun toDataType() = BlockDescriptor1DataType(program.dataTypeManager)
}

/**
 * The second part of a block descriptor in the given program.
 */
class BlockDescriptor2(
    private var program: Program,
    buffer: ByteBuffer,
) : BlockDescriptorPart() {
    val copyHelperPointer = buffer.getLong()
    val disposeHelperPointer = buffer.getLong()

    override fun toDataType() = BlockDescriptor2DataType(program.dataTypeManager)
}

/**
 * The third part of a block descriptor in the given program.
 */
class BlockDescriptor3(
    private var program: Program,
    buffer: ByteBuffer,
) : BlockDescriptorPart() {
    val signaturePointer = buffer.getLong()
    val layout = buffer.getLong()

    val encodedSignature get() =
        {
            signaturePointer.let {
                val signatureString =
                    program.listing
                        .getDataAt(program.address(it))
                        .bytes
                        .decodeToString()
                parseSignature(signatureString, EncodedSignatureType.BLOCK_SIGNATURE)
            }
        }()

    override fun toDataType() = BlockDescriptor3DataType(program.dataTypeManager)
}
