package lol.fairplay.ghidraapple.analysis.passes.blocks

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.markasblock.ApplyNSConcreteGlobalBlock

class ObjectiveCGlobalBlockAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {
    companion object {
        const val NAME = "Objective-C Blocks: Global Blocks"
        private const val DESCRIPTION = "Analyzes the program for Objective-C global blocks."
    }

    init {
        priority = AnalysisPriority.DATA_TYPE_PROPOGATION
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean =
        program
            .symbolTable
            .let {
                it.getSymbols("__NSConcreteGlobalBlock").firstOrNull() != null ||
                    it.getSymbols("__NSGlobalBlock__").firstOrNull() != null
            }

    /**
     * We find all locations in the [AddressSetView] that reference the [globalBlockSymbol]
     * and call [markGlobalBlock] on them.
     */
    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        val globalBlockSymbol = program.symbolTable.getSymbols("__NSConcreteGlobalBlock").first()
        val globalBlockAliasSymbol = program.symbolTable.getSymbols("__NSGlobalBlock__").first()
        program.referenceManager
            .let { it.getReferencesTo(globalBlockSymbol.address) + it.getReferencesTo(globalBlockAliasSymbol.address) }
            .filter { set.contains(it.fromAddress) }
            .filter { it.referenceType == RefType.DATA }
            .filter { program.memory.getBlock(it.fromAddress)?.name == "__const" }
            .forEach {
                ApplyNSConcreteGlobalBlock(it.fromAddress).applyTo(program)
            }
        return true
    }
}
