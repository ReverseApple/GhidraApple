package lol.fairplay.ghidraapple.analysis.passes.blocks

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.markasblock.MarkNSConcreteGlobalBlock
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.FindGlobalBlockSymbolPointers
import lol.fairplay.ghidraapple.analysis.utilities.getReferencesToSymbol

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

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        program
            .let { it.getReferencesToSymbol("__NSConcreteGlobalBlock") + it.getReferencesToSymbol("__NSGlobalBlock__") }
            .filter { set.contains(it.fromAddress) }
            .filter { it.referenceType == RefType.DATA }
            .filter { program.memory.getBlock(it.fromAddress)?.name == "__const" }
            .map { it.fromAddress }
            .toSet()
            .let { referenceAddresses ->
                // TODO: This might be expensive in some binaries. Should we hide it behind an option?
                FindGlobalBlockSymbolPointers().let {
                    it.applyTo(program)
                    referenceAddresses + it.addresses
                }
            }.forEach {
                MarkNSConcreteGlobalBlock(it).applyTo(program)
            }
        return true
    }
}
