package lol.fairplay.ghidraapple.analysis.passes.blocks

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.markasblock.MarkNSConcreteStackBlock
import lol.fairplay.ghidraapple.analysis.utilities.getReferencesToSymbol

class ObjectiveCStackBlockAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER) {
    companion object {
        const val NAME = "Objective-C Blocks: Stack Blocks"
        private const val DESCRIPTION = "Analyzes the program for Objective-C stack blocks."
    }

    init {
        priority = AnalysisPriority.LOW_PRIORITY
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean =
        program
            .symbolTable
            .let {
                it.getSymbols("__NSConcreteStackBlock").firstOrNull() != null ||
                    it.getSymbols("__NSStackBlock__").firstOrNull() != null
            }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        program
            .let {
                it.getReferencesToSymbol("__NSConcreteStackBlock") + it.getReferencesToSymbol("__NSStackBlock__")
            }.filter { set.contains(it.fromAddress) }
            .filter { reference -> reference.referenceType == RefType.DATA && reference.source == SourceType.ANALYSIS }
            .also { monitor.maximum = it.size.toLong() }
            .stream()
            .parallel()
            .forEach { reference ->
                monitor.checkCancelled()
                MarkNSConcreteStackBlock(
                    program.listing.getFunctionContaining(reference.fromAddress),
                    program.listing.getInstructionAt(reference.fromAddress),
                ).applyTo(program)
                monitor.incrementProgress()
            }
        return true
    }
}
