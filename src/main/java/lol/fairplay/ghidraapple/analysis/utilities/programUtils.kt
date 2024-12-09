package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Symbol
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.derefUntyped
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.get

/**
 * Converts a given long value to an Address object using the default address space.
 *
 * @param value The long value to be converted to an Address.
 * @return The Address object corresponding to the given long value.
 */
fun Program.address(value: Long): Address {
    return this.addressFactory.defaultAddressSpace.getAddress(value)
}

fun tryResolveNamespace(program: Program, vararg fqnParts: String): Namespace? {
    var ns = program.globalNamespace
    for (part in fqnParts) {
        ns = program.symbolTable.getNamespace(part, ns) ?: return null
    }
    return ns
}

fun Namespace.getMembers(): Iterable<Symbol> {
    return this.symbol.program.symbolTable.getChildren(this.symbol)
}

fun dataBlocksForNamespace(program: Program, ns: Namespace, addresses: AddressSetView): List<Data> {
    var dataBlocks = program.listing.getDefinedData(addresses, true)
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
    val result = mapOf<String, Data>()
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

fun parseObjCListSection(program: Program, sectionName: String): List<Data>? {
    val sectionBlock = program.memory.getBlock(sectionName) ?: return null
    val entries = sectionBlock.size / 8
    val start = sectionBlock.start

    return (0 until entries).map {
        val datAddress = program.listing
            .getDataAt(start.add(it * 8))
            .getPrimaryReference(0)
            .toAddress
        program.listing.getDefinedDataAt(datAddress)
    }
}

fun dataAt(program: Program, address: Address): Data? =
    program.listing.getDefinedDataAt(address)



