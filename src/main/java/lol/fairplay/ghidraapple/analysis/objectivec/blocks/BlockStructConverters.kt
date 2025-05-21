package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.util.bin.StructConverter
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataType.DEFAULT
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StringDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.TerminatedStringDataType
import ghidra.program.model.data.Undefined
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

// Class property initializations are **guaranteed** by spec to be invoked in the order they appear in the class body.
// https://github.com/Kotlin/kotlin-spec/blob/release/docs/src/md/kotlin.core/declarations.md?plain=1#L881

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

    /**
     * A flag for a block layout.
     */
    enum class Flag(
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

    val flagsBitfield = buffer.getInt()
    val flags: Set<Flag> =
        Flag.entries
            .filter { (flagsBitfield and it.value) != 0 }
            .toSet()

    val reserved = buffer.getInt()
    val invokePointer = buffer.getLong()
    val descriptorPointer = buffer.getLong()

    // A block has a descriptor, starting with, at the very least, a `Block_descriptor_1` struct. This is
    //  then followed by (optionally) a `Block_descriptor_2` struct and/or a `Block_descriptor_3` struct,
    //  with the included structs being laid out in memory in ascending numerical order.

    // All values relating to descriptors beyond the first struct are defined as getters, as they should
    //  not be calculated during initialization. They will be used later when marking up the structs.

    private val descriptorHasCopyDispose get() = Flag.BLOCK_HAS_COPY_DISPOSE in flags
    private val descriptorHasSignature get() = Flag.BLOCK_HAS_SIGNATURE in flags

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
                typeResolver.buildParsed(it.returnType.first)
                    ?: run {
                        // We don't fail here because the return value is not memory-critical.
                        Msg.debug(
                            this,
                            "Failed to resolve return type for block with descriptor address $descriptor1Address.",
                        )
                        // TODO: Is it ok to fallback to an eight-byte value for unknown return types?
                        Undefined.getUndefinedDataType(8)
                    }
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
        } ?: return Pair(Undefined.getUndefinedDataType(8), emptyArray())
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
                        CreateFunctionCmd(null, invokeAddress, null, SourceType.ANALYSIS, false, false)
                            .applyTo(program)
                        // Return the newly-created function.
                        program.listing.getFunctionAt(invokeAddress)
                    }
            }.let {
                it.setName("invoke_$invokeAddress", SourceType.ANALYSIS)
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
            val minimalBlockType = BlockLayoutDataType(program.dataTypeManager)
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
        val defaultReturnTypeAndParameters =
            Pair(VoidDataType.dataType, emptyArray<ParameterDefinitionImpl>())
        val (blockReturnType, blockParameters) =
            if (program.currentTransactionInfo != null) {
                try {
                    generateDataTypesFromEncodedSignature()
                } catch (_: NotImplementedError) {
                    // TODO: Trying to decode a signature with a bitfield is currently unsupported and throws
                    //  a [NotImplementedError]. We should remove this when we add support for bitfields.
                    defaultReturnTypeAndParameters
                } catch (e: Throwable) {
                    Msg.warn(
                        this,
                        "Failed to parse signature: ${this.descriptor3!!.signatureString}. " +
                            "Throwable: $e",
                    )
                    defaultReturnTypeAndParameters
                }
            } else {
                defaultReturnTypeAndParameters
            }
        val minimalBlockSize = BlockLayoutDataType(program.dataTypeManager).length
        val actualBlockSize = descriptor1.blockSize
        val extraBytes = (actualBlockSize - minimalBlockSize).toInt()
        return BlockLayoutDataType(
            program.dataTypeManager,
            dataTypeSuffix,
            program.address(invokePointer).toString(),
            blockReturnType,
            blockParameters,
            // We don't know what the imported variables are, but at least we know how long they are. For now,
            //  we'll just put in undefined bytes and allow the user to re-type the struct as necessary.
            generateSequence(Triple(DEFAULT, "", null)) { it }.take(extraBytes).toList().toTypedArray(),
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

    val signatureString get() =
        program.listing
            .getDataAt(program.address(signaturePointer))
            .let {
                if (it.dataType != StringDataType.dataType) {
                    // If this isn't a string data type, we need to make it one.
                    program.withTransaction<Exception>("Mark Block Signature as String") {
                        DataUtilities.createData(
                            program,
                            it.address,
                            TerminatedStringDataType.dataType,
                            -1,
                            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                        )
                    }
                    it
                } else {
                    // Otherwise, just keep it as-is.
                    it
                }
            }.bytes
            .decodeToString()

    val encodedSignature: EncodedSignature get() =
        parseSignature(signatureString, EncodedSignatureType.BLOCK_SIGNATURE)

    override fun toDataType() = BlockDescriptor3DataType(program.dataTypeManager)
}

class BlockByRef(
    private var program: Program,
    buffer: ByteBuffer,
    private val dataTypeSuffix: String? = null,
    minimal: Boolean = false,
) : StructConverter {
    val isa = buffer.getLong()
    val forwarding = buffer.getLong()

    enum class Flag(
        val value: Int,
    ) {
        BLOCK_BYREF_LAYOUT_MASK(0xf shl 28),
        BLOCK_BYREF_LAYOUT_EXTENDED(1 shl 28),
        BLOCK_BYREF_LAYOUT_NON_OBJECT(2 shl 28),
        BLOCK_BYREF_LAYOUT_STRONG(3 shl 28),
        BLOCK_BYREF_LAYOUT_WEAK(4 shl 28),
        BLOCK_BYREF_LAYOUT_UNRETAINED(5 shl 28),
        BLOCK_BYREF_IS_GC(1 shl 27),
        BLOCK_BYREF_HAS_COPY_DISPOSE(1 shl 25),
        BLOCK_BYREF_NEEDS_FREE(1 shl 24),
    }

    val flagsBitfield = buffer.getInt()
    val flags =
        Flag.entries
            .filter { (flagsBitfield and it.value) != 0 }
            .toSet()

    val size = buffer.getInt().toUInt()

    val hasBlockByRef2 = Flag.BLOCK_BYREF_HAS_COPY_DISPOSE in flags
    val hasBlockByRef3 = Flag.BLOCK_BYREF_LAYOUT_EXTENDED in flags

    val keepFunctionPointer = if (hasBlockByRef2 && !minimal) buffer.getLong() else null
    val destroyFunctionPointer = if (hasBlockByRef2 && !minimal) buffer.getLong() else null

    val layoutPointer = if (hasBlockByRef3 && !minimal) buffer.getLong() else null

    override fun toDataType() =
        BlockByRefDataType(
            program.dataTypeManager,
            dataTypeSuffix,
            size,
            hasBlockByRef2,
            hasBlockByRef3,
        )
}
