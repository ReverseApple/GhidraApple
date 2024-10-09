package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace


fun tryResolveNamespace(program: Program, vararg fqnParts: String): Namespace?  {
    var ns = program.globalNamespace
    for (part in fqnParts) {
        ns = program.symbolTable.getNamespace(part, ns) ?: return null
    }
    return ns
}