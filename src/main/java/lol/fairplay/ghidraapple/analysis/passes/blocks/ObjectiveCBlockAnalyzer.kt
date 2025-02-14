package lol.fairplay.ghidraapple.analysis.passes.blocks

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.markasblock.markGlobalBlock
import lol.fairplay.ghidraapple.actions.markasblock.markStackBlock

class ObjectiveCBlockAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {
    companion object {
        const val NAME = "Objective-C: Blocks"
        private const val DESCRIPTION = "Analyzes the program for Objective-C blocks."
    }

    var globalBlockSymbol: Symbol? = null
    var stackBlockSymbol: Symbol? = null

    init {
        priority = AnalysisPriority.DATA_TYPE_PROPOGATION.after()
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean {
        globalBlockSymbol = program.symbolTable.getSymbols("__NSConcreteGlobalBlock").firstOrNull()
        stackBlockSymbol = program.symbolTable.getSymbols("__NSConcreteStackBlock").firstOrNull()
        return (globalBlockSymbol != null || stackBlockSymbol != null)
    }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        globalBlockSymbol?.let {
            for (reference in program.referenceManager.getReferencesTo(it.address)) {
                if (reference.referenceType == RefType.DATA) {
                    try {
                        markGlobalBlock(program, reference.fromAddress)
                    } catch (e: Exception) {
                        println("Failed to mark global block at address 0x${reference.fromAddress} \n\t ${e.message}")
                    }
                }
            }
        }
        stackBlockSymbol?.let {
            for (reference in program.referenceManager.getReferencesTo(it.address)) {
                if (reference.referenceType == RefType.DATA && reference.source == SourceType.ANALYSIS) {
                    try {
                        markStackBlock(
                            program,
                            program.listing.getFunctionContaining(reference.fromAddress),
                            program.listing.getInstructionAt(reference.fromAddress),
                        )
                    } catch (e: Exception) {
                        println("Failed to mark stack block at address 0x${reference.fromAddress} \n\t ${e.message}")
                    }
                }
            }
        }
        return true
    }
}
