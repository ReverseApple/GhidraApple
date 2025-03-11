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
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.markasblock.ApplyNSConcreteStackBlock
import java.util.LinkedList

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
        program.symbolTable.getSymbols("__NSConcreteStackBlock").firstOrNull()?.let {
            // TODO: The current use of the queue makes the logic hard to follow.
            //  It would be better to first collect all the references and then process them.
            //  This also allows easier debugging if e.g. a reference is missing
            //  And it makes it possible to determine the needed degree of parallelization based on the amount of references.

            // We parallelize as some runs of [markStackBlock] may trigger the decompiler.
            ConcurrentQ<Reference, Nothing>(
                object : QCallback<Reference, Nothing> {
                    override fun process(
                        reference: Reference,
                        monitor: TaskMonitor?,
                    ): Nothing? {
                        if (reference.referenceType == RefType.DATA && reference.source == SourceType.ANALYSIS) {
                            ApplyNSConcreteStackBlock(
                                program.listing.getFunctionContaining(reference.fromAddress),
                                program.listing.getInstructionAt(reference.fromAddress),
                            ).applyTo(program)
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
                        Msg.warn(
                            this,
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
