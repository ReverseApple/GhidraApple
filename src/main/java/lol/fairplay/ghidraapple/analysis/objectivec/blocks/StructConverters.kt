package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.app.util.bin.StructConverter
import ghidra.program.model.address.Address
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
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
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
 * An Objective-C block (relevant to the given program) with the layout representation contained in the given buffer.
 */
class BlockLayout(
    private val program: Program,
    buffer: ByteBuffer,
    private val dataTypeSuffix: String? = null,
) : StructConverter {
    val isaPointer =
        buffer.getLong().also { it ->
            val isaSymbol =
                program.symbolTable
                    .getSymbols(program.addressFactory.defaultAddressSpace.getAddress(it))
                    .firstOrNull { it.isPrimary }
                    ?: throw IOException("The `isa` field of the block doesn't point to a known symbol.")
            if (isaSymbol.name !in
                listOf(
                    "__NSConcreteStackBlock",
                    "__NSConcreteMallocBlock",
                    "__NSConcreteAutoBlock",
                    "__NSConcreteFinalizingBlock",
                    "__NSConcreteGlobalBlock",
                    "__NSConcreteWeakBlockVariable",
                )
            ) {
                throw IOException("The `isa` field of the block doesn't point to a valid target.")
            }
        }
    val flagsBitfield = buffer.getInt()
    val flags: Set<BlockFlag> =
        BlockFlag.entries
            .filter { (flagsBitfield and it.value) != 0 }
            .toSet()
    val reserved = buffer.getInt()
    val invokePointer = buffer.getLong()
    val descriptorPointer = buffer.getLong()

    private var memoryAddress: Address? = null

    private val descriptorHasCopyDispose = flags.contains(BlockFlag.BLOCK_HAS_COPY_DISPOSE)
    private val descriptorHasSignature = flags.contains(BlockFlag.BLOCK_HAS_SIGNATURE)

    private val descriptor1Address = program.addressFactory.defaultAddressSpace.getAddress(descriptorPointer)
    private val descriptor2Address =
        if (descriptorHasCopyDispose) {
            program.addressFactory.defaultAddressSpace
                .getAddress(descriptorPointer)
                .add(BlockDescriptor1DataType(program.dataTypeManager).length.toLong())
        } else {
            null
        }
    private val descriptor3Address =
        if (descriptorHasSignature) {
            program.addressFactory.defaultAddressSpace
                .getAddress(descriptorPointer)
                .add(BlockDescriptor1DataType(program.dataTypeManager).length.toLong())
                .apply {
                    if (descriptorHasCopyDispose) {
                        add(BlockDescriptor2DataType(program.dataTypeManager).length.toLong())
                    }
                }
        } else {
            null
        }

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

    val descriptor1 =
        readDescriptorPart(
            descriptor1Address,
            BlockDescriptor1DataType(program.dataTypeManager).length,
        ) { BlockDescriptor1(program, it) }

    val descriptor2 =
        descriptor2Address?.let {
            readDescriptorPart(
                it,
                BlockDescriptor2DataType(program.dataTypeManager).length,
            ) { BlockDescriptor2(program, it) }
        }

    val descriptor3 =
        descriptor3Address?.let {
            readDescriptorPart(
                it,
                BlockDescriptor3DataType(program.dataTypeManager).length,
            ) { BlockDescriptor3(program, it) }
        }

    val encodedSignature = descriptor3?.encodedSignature

    /**
     * Generates data types from the encoded signature. MUST be executed from a transaction.
     */
    fun generateDataTypesFromEncodedSignature(): Pair<DataType, Array<ParameterDefinitionImpl>> {
        if (encodedSignature != null) {
            val typeResolver = TypeResolver(program)
            val returnType =
                typeResolver.buildParsed(encodedSignature.returnType.first) ?: {
                    // We don't fail here because the return value is not memory-critical.
                    println("Failed to resolve return type for block with descriptor address $descriptor1Address.")
                    VoidDataType.dataType
                }()
            val parameters =
                encodedSignature.parameters
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
        } else {
            return Pair(VoidDataType.dataType, emptyArray())
        }
    }

    /**
     * Marks up the block in the program, assuming it is at the given address.
     */
    private fun markupBlock(address: Address) {
        DataUtilities.createData(
            program,
            address,
            this.toDataType(),
            -1,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
        )
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
                this.descriptor2.toDataType(),
                -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
        }
        descriptor3?.let {
            if (descriptor3Address == null) return
            DataUtilities.createData(
                program,
                descriptor3Address,
                this.descriptor3.toDataType(),
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
        if (BlockFlag.BLOCK_HAS_SIGNATURE !in flags) return
        // We "steal" the invoke function definition from the data type.
        val invokeFunctionType =
            (
                (this.toDataType() as? StructureDataType)
                    ?.components
                    ?.firstOrNull { it.fieldName == "invoke" }
                    ?.dataType as? PointerDataType
            )?.dataType as? FunctionDefinitionDataType ?: return
        program.listing
            .getFunctionAt(program.addressFactory.defaultAddressSpace.getAddress(invokePointer))
            .let {
                it.updateFunction(
                    it.callingConventionName, // Keep the same calling convention
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
    fun updateProgram() {
        this.memoryAddress?.let { markupBlock(it) }
        markupDescriptorParts()
        updateInvokeFunction()
    }

    /**
     * An in-memory block that lives at the given address in the given program.
     */
    constructor(program: Program, address: Address) : this(
        program,
        {
            val minimalBlockType =
                BlockLayoutDataType(
                    program.dataTypeManager,
                    address.toString(),
                    VoidDataType.dataType,
                    emptyArray(),
                    emptyArray(),
                )
            val blockBytes = ByteArray(minimalBlockType.length)
            val bytesRead = program.memory.getBytes(address, blockBytes)
            if (bytesRead != blockBytes.size) {
                throw IOException("Unable to read the ${blockBytes.size} needed to parse a global block.")
            }
            ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN)
        }(),
        address.toString(),
    ) {
        this.memoryAddress = address
    }

    override fun toDataType(): DataType {
        val (blockReturnType, blockParameters) =
            if (program.currentTransactionInfo != null) {
                generateDataTypesFromEncodedSignature()
            } else {
                Pair(VoidDataType.dataType, emptyArray())
            }
        val minimalBlockSize =
            BlockLayoutDataType(
                program.dataTypeManager,
                dataTypeSuffix,
                VoidDataType.dataType,
                emptyArray(),
                emptyArray(),
            ).length
        val actualBlockSize = descriptor1.blockSize
        return BlockLayoutDataType(
            program.dataTypeManager,
            dataTypeSuffix,
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

    val encodedSignature: EncodedSignature =
        {
            signaturePointer.let {
                val signatureString =
                    program.listing
                        .getDataAt(program.addressFactory.defaultAddressSpace.getAddress(it))
                        .bytes
                        .decodeToString()
                parseSignature(signatureString, EncodedSignatureType.BLOCK_SIGNATURE)
            }
        }()

    override fun toDataType() = BlockDescriptor3DataType(program.dataTypeManager)
}
