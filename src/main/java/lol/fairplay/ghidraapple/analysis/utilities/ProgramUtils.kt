package lol.fairplay.ghidraapple.analysis.utilities

import docking.widgets.table.AbstractDynamicTableColumn
import docking.widgets.table.TableColumnDescriptor
import ghidra.docking.settings.Settings
import ghidra.framework.plugintool.ServiceProvider
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.PcodeOpAST
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.ReferenceIterator
import ghidra.program.model.symbol.ReferenceIteratorAdapter
import ghidra.program.model.symbol.ReferenceManager
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolType
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.derefUntyped
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.get
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Converts a given long value to an Address object using the default address space.
 *
 * @param value The long value to be converted to an Address.
 * @return The Address object corresponding to the given long value.
 */
fun Program.address(value: Long): Address = this.addressFactory.defaultAddressSpace.getAddress(value)

fun tryResolveNamespace(
    program: Program,
    vararg fqnParts: String,
): Namespace? {
    var ns = program.globalNamespace
    for (part in fqnParts) {
        ns = program.symbolTable.getNamespace(part, ns) ?: return null
    }
    return ns
}

fun Namespace.getMembers(): Iterable<Symbol> =
    this.symbol.program.symbolTable
        .getChildren(this.symbol)

fun dataBlocksForNamespace(
    program: Program,
    ns: Namespace,
    addresses: AddressSetView,
): List<Data> {
    var dataBlocks =
        program.listing
            .getDefinedData(addresses, true)
            .filter { data ->
                val primarySymbol = data.primarySymbol
                val parentNamespace = primarySymbol?.parentNamespace
                primarySymbol != null &&
                    parentNamespace != null &&
                    parentNamespace.getName(true) == ns.getName(true)
            }

    return dataBlocks
}

@Deprecated("Use parseObjCListSection instead.")
fun idealClassStructures(program: Program): Map<String, Data>? {
    val namespace = tryResolveNamespace(program, "objc", "class_t") ?: return null

    val idealStructures = mutableMapOf<String, Data>()
    namespace.getMembers().forEach { member ->
        if (member.name !in idealStructures) {
            idealStructures[member.name] = program.listing.getDefinedDataAt(member.address)
        } else {
            val data = idealStructures[member.name]!!
            val superclassExisting = data[0].derefUntyped()
            if (superclassExisting.primarySymbol.name.startsWith("_OBJC_METACLASS_\$")) {
                idealStructures[member.name] = program.listing.getDefinedDataAt(member.address)
            }
        }
    }

    return idealStructures
}

fun parseObjCListSection(
    program: Program,
    sectionName: String,
): List<Data>? {
    val sectionBlock = program.memory.getBlock(sectionName) ?: return null
    val entries = sectionBlock.size / 8
    val start = sectionBlock.start

    return (0 until entries).map {
        val pointerAddress = start.add(it * 8)
        var data = program.listing.getDataAt(pointerAddress)
        if (!data.isPointer) {
            data = program.listing.createData(pointerAddress, PointerDataType.dataType)
        }
        val datAddress =
            data
                .getPrimaryReference(0)
                .toAddress
        program.listing.getDefinedDataAt(datAddress)
    }
}

fun dataAt(
    program: Program,
    address: Address,
): Data? = program.listing.getDefinedDataAt(address)

fun ReferenceManager.setCallTarget(
    callsite: Address,
    targetFunction: Function,
    sourceType: SourceType,
) {
    val ref = addMemoryReference(callsite, targetFunction.entryPoint, RefType.UNCONDITIONAL_CALL, sourceType, 0)
    setPrimary(ref, true)
}

fun <ROW_TYPE, COLUMN_TYPE> TableColumnDescriptor<ROW_TYPE>.addColumn(
    name: String,
    visible: Boolean,
    columnType: Class<COLUMN_TYPE>,
    accessor: (ROW_TYPE) -> COLUMN_TYPE?,
) {
    val column =
        object : AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Any?>() {
            override fun getColumnName(): String = name

            override fun getValue(
                rowObject: ROW_TYPE,
                settings: Settings,
                data: Any?,
                serviceProvider: ServiceProvider,
            ): COLUMN_TYPE? = accessor(rowObject)

            override fun getColumnClass(): Class<COLUMN_TYPE> = columnType
        }
    if (visible) {
        addVisibleColumn(column)
    } else {
        addHiddenColumn(column)
    }
}

/**
 * Returns a [ByteArray] of the given [size], taken from the given [address].
 *
 * @throws [IllegalStateException] If a [ByteArray] of the given [size] cannot be taken from the given [address].
 */
fun Memory.getBytes(
    address: Address,
    size: Int,
): ByteArray {
    val bytes = ByteArray(size)
    val bytesGotten = getBytes(address, bytes)
    if (bytesGotten != size) throw IllegalStateException("Unable to get $size bytes at 0x$address.")
    return bytes
}

fun Memory.getByteOrder(): ByteOrder = if (isBigEndian) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN

/**
 * Gets the bytes of a [Varnode] within the given [program]. Only works in simple cases.
 */
fun Varnode.getBytes(program: Program): ByteArray =
    when {
        address.isMemoryAddress ->
            program.memory.getBytes(address, size)

        address.isConstantAddress ->
            ByteBuffer
                // We allocate as much space as we need and will truncate later.
                .allocate(Long.SIZE_BYTES)
                .order(program.memory.getByteOrder())
                .putLong(address.offset)
                .let {
                    when (it.order()) {
                        ByteOrder.LITTLE_ENDIAN -> it.array().copyOfRange(0, size)
                        // We just did [putLong], so the position should be at the end.
                        ByteOrder.BIG_ENDIAN -> it.array().copyOfRange(it.position() - size, it.position())
                        // This should never happen, but it's here to make the compiler happy.
                        else -> throw IllegalStateException("Unsupported byte order: ${it.order()}!")
                    }
                }

        address.isUniqueAddress ->
            def.inputs
                // If they're all the same, we can probably just continue.
                .let { inputs -> if (inputs.all { it.address == inputs.first()?.address }) inputs else null }
                // Take the first one.
                ?.first()
                // TODO: This sometimes results in a buffer overflow :(
                ?.getBytes(program) ?: ByteArray(0)
        else -> throw IllegalStateException("Unexpected Varnode.")
    }

/**
 * Gets the bytes that this operation puts into the output [Varnode].
 */
fun PcodeOpAST.getOutputBytes(program: Program): ByteArray? {
    if (!isAssignment) return null
    return when (opcode) {
        PcodeOp.COPY -> inputs[0].getBytes(program).copyOfRange(0, output.size)
        PcodeOp.SUBPIECE ->
            inputs[0]
                .getBytes(program)
                .let {
                    val fromIndex =
                        inputs[1]
                            .apply { assert(isConstant) }
                            .address.offset
                            .toInt()
                    it.copyOfRange(fromIndex, fromIndex + output.size)
                }
        else -> null
    }
}

/**
 * Geta a list of addresses for symbols that match the given name.
 */
fun Program.getAddressesOfSymbol(
    symbolName: String,
    allowExternal: Boolean = false,
): List<Address> =
    symbolTable
        .getSymbols(symbolName)
        .let { if (allowExternal) it else it.filter { !it.address.isExternalAddress } }
        .map { it.address }

/**
 * Gets an iterator of references in the program to a symbol with the given name.
 */
fun Program.getReferencesToSymbol(symbolName: String): ReferenceIterator =
    ReferenceIteratorAdapter(
        getAddressesOfSymbol(symbolName)
            .flatMap {
                referenceManager.getReferencesTo(it)
            }.iterator(),
    )

/**
 * Gets a sequence of address in the program that contain an address of a symbol with the given name.
 */
fun Program.getPointersToSymbol(
    symbolName: String,
    block: MemoryBlock,
): Sequence<Address> = getPointersToSymbol(symbolName, block.start, block.end)

/**
 * Gets a sequence of address in the program that contain an address of a symbol with the given name.
 */
fun Program.getPointersToSymbol(
    symbolName: String,
    startAddress: Address = minAddress,
    endAddress: Address = maxAddress,
): Sequence<Address> =
    getAddressesOfSymbol(symbolName)
        .map { it.offset }
        .let { symbolAddressOffsets ->
            generateSequence(startAddress) { it.add(defaultPointerSize.toLong()) }
                .takeWhile { it <= endAddress }
                .filter { addressToFilter ->
                    try {
                        val pointerBytes = ByteArray(defaultPointerSize)
                        val bytesRead = memory.getBytes(addressToFilter, pointerBytes)
                        if (bytesRead != pointerBytes.size) return@filter false
                        ByteBuffer
                            .allocate(defaultPointerSize)
                            .order(if (memory.isBigEndian) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN)
                            .put(pointerBytes)
                            .flip()
                            .let {
                                return@filter symbolAddressOffsets.contains(
                                    when (defaultPointerSize) {
                                        4 -> it.int.toLong()
                                        8 -> it.long
                                        else -> return@filter false
                                    },
                                )
                            }
                        return@filter false
                    } catch (_: Exception) {
                        return@filter false
                    }
                }
        }

/**
 * Gets the label at the given address in the program, if one exists.
 */
fun Program.getLabelAtAddress(address: Address): String? =
    symbolTable.getPrimarySymbol(address).takeIf { it?.symbolType == SymbolType.LABEL }?.name
