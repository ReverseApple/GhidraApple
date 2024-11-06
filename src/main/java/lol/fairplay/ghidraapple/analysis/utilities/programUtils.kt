package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace


fun tryResolveNamespace(program: Program, vararg fqnParts: String): Namespace?  {
    var ns = program.globalNamespace
    for (part in fqnParts) {
        ns = program.symbolTable.getNamespace(part, ns) ?: return null
    }
    return ns
}

fun dataBlocksForNamespace(program: Program, ns: Namespace, addresses: AddressSet): List<Data> {
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
