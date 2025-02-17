package lol.fairplay.ghidraapple.analysis.passes.blocks

import generic.concurrent.ConcurrentQ
import generic.concurrent.GThreadPool
import generic.concurrent.QCallback
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.markasblock.markStackBlock
import java.util.LinkedList

class ObjectiveCStackBlockAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER) {
    companion object {
        const val NAME = "Objective-C: Stack Blocks"
        private const val DESCRIPTION = "Analyzes the program for Objective-C stack blocks."
    }

    var stackBlockSymbol: Symbol? = null

    init {
        priority = AnalysisPriority.LOW_PRIORITY
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean {
        stackBlockSymbol = program.symbolTable.getSymbols("__NSConcreteStackBlock").firstOrNull()
        return (stackBlockSymbol != null)
    }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        stackBlockSymbol?.let {
            // We parallelize as some runs of [markStackBlock] may trigger the decompiler.
            ConcurrentQ<Reference, Nothing>(
                object : QCallback<Reference, Nothing> {
                    override fun process(
                        reference: Reference,
                        monitor: TaskMonitor?,
                    ): Nothing? {
                        if (reference.referenceType == RefType.DATA && reference.source == SourceType.ANALYSIS) {
                            markStackBlock(
                                program,
                                program.listing.getFunctionContaining(reference.fromAddress),
                                program.listing.getInstructionAt(reference.fromAddress),
                            )
                        }
                        return null
                    }
                },
                // [ConcurrentQ] doesn't seem to support passing in a filled [LinkedList] as a constructor
                //  parameter, so we instead pass an empty list. The references will be added below.
                LinkedList(),
                GThreadPool.getPrivateThreadPool("Stack Block Parser Thread Pool"),
                null,
                true,
                0,
                false,
            ).apply {
                add(
                    program.referenceManager.getReferencesTo(it.address).filter {
                        set.contains(it.fromAddress)
                    },
                )
                for (result in waitForResults()) {
                    result.error?.let {
                        println(
                            "Parsing failed for stack block with address ${result.item.fromAddress}.",
                        )
                        it.printStackTrace()
                    }
                }
                dispose()
            }
        }
        return true
    }
}
