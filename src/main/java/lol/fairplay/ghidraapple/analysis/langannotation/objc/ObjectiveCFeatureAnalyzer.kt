package lol.fairplay.ghidraapple.analysis.langannotation.objc

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.selectortrampoline.SelectorTrampolineAnalyzer
import lol.fairplay.ghidraapple.core.common.MachOCpuID


class ObjectiveCFeatureAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {

    companion object {
        const val NAME = "Objective-C Language Feature Analysis"
        const val DESCRIPTION = "This feature is experimental and not recommended for use yet."
        val PRIORITY: AnalysisPriority = SelectorTrampolineAnalyzer.PRIORITY.after()
    }

    init {
        setPrototype()
        priority = PRIORITY
    }

    override fun canAnalyze(program: Program?): Boolean {
        val cpu = MachOCpuID.getCPU(program!!) ?: return false
        return cpu == MachOCpuID.AARCH64 || cpu == MachOCpuID.AARCH64E
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val selector_tag = program.functionManager
            .functionTagManager.getFunctionTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)

        if (selector_tag == null) {
            throw Exception("ObjectiveCFeatureAnalyzer depends on the SelectorTrampolineAnalyzer pass.")
        }

        val objc_trampoline_tag = program.functionManager
            .functionTagManager.getFunctionTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)

        val xrefFunctions = hashSetOf<Function>()

        val functions = set.getAddresses(true).toList().mapNotNull { address ->
            val function = program.functionManager.getFunctionAt(address)
            if (function.tags.contains(objc_trampoline_tag)) {
                // While we're at it, get all the referencing functions to the trampolines
                xrefFunctions.addAll(
                    program
                        .referenceManager
                        .getReferencesTo(function.symbol.address).map {
                            program.functionManager.getFunctionAt(it.toAddress)
                        }
                )
                function
            } else {
                null
            }
        }

        TODO()
    }

}
