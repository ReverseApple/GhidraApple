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
import lol.fairplay.ghidraapple.actions.markasblock.ApplyNSConcreteStackBlock

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
            .getSymbols("__NSConcreteStackBlock")
            .firstOrNull() != null

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        val stackBlockSymbol = program.symbolTable.getSymbols("__NSConcreteStackBlock").first()
        val stackBlockAliasSymbol = program.symbolTable.getSymbols("__NSStackBlock__").first()
        val references =
            program.referenceManager
                .let {
                    it.getReferencesTo(stackBlockSymbol.address) + it.getReferencesTo(stackBlockAliasSymbol.address)
                }.filter { set.contains(it.fromAddress) }

        references.stream().parallel()
            .filter { reference -> reference.referenceType == RefType.DATA && reference.source == SourceType.ANALYSIS }
            .forEach { reference ->
                ApplyNSConcreteStackBlock(
                    program.listing.getFunctionContaining(reference.fromAddress),
                    program.listing.getInstructionAt(reference.fromAddress),
                ).applyTo(program)
            }
        return true
    }
}
