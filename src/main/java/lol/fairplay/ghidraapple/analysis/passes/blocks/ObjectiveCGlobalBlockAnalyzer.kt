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
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.markasblock.markGlobalBlock
import java.util.LinkedList

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
            .getSymbols("__NSConcreteGlobalBlock")
            .firstOrNull() != null

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        program.symbolTable.getSymbols("__NSConcreteGlobalBlock").firstOrNull()?.let {
            ConcurrentQ<Reference, Nothing>(
                object : QCallback<Reference, Nothing> {
                    override fun process(
                        reference: Reference,
                        monitor: TaskMonitor?,
                    ): Nothing? {
                        if (reference.referenceType == RefType.DATA) {
                            markGlobalBlock(program, reference.fromAddress)
                        }
                        return null
                    }
                },
                // [ConcurrentQ] doesn't seem to support passing in a filled [LinkedList] as a constructor
                //  parameter, so we instead pass an empty list. The references will be added below.
                LinkedList(),
                GThreadPool.getPrivateThreadPool("Global Block Parser Thread Pool"),
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
                            "Parsing failed for global block with address ${result.item.fromAddress}.",
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
