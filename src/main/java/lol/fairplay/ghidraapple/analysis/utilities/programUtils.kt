package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace

/**
 * Converts a given long value to an Address object using the default address space.
 *
 * @param value The long value to be converted to an Address.
 * @return The Address object corresponding to the given long value.
 */
fun Program.address(value: Long): Address {
    return this.addressFactory.defaultAddressSpace.getAddress(value)
}

fun tryResolveNamespace(program: Program, vararg fqnParts: String): Namespace?  {
    var ns = program.globalNamespace
    for (part in fqnParts) {
        ns = program.symbolTable.getNamespace(part, ns) ?: return null
    }
    return ns
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
