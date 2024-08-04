package lol.fairplay.ghidraapple.analysis.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor


class OCStructureAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {

    companion object {
        private const val NAME = "Objective-C Structures"
        private const val DESCRIPTION = "Parse Objective-C class structures"
        private val PRIORITY = AnalysisPriority.BLOCK_ANALYSIS.after()
    }

    init {
        priority = PRIORITY
    }

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        TODO("Not yet implemented.")
    }

}
