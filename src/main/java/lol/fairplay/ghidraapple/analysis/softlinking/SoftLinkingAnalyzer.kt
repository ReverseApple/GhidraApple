package lol.fairplay.ghidraapple.analysis.softlinking

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.MachoLoader
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

class SoftLinkingAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, TYPE) {

    private lateinit var program: Program

    companion object {
        const val NAME = "SoftLinkingAnalyzer"
        const val DESCRIPTION = ""
        val TYPE = AnalyzerType.FUNCTION_ANALYZER
    }

    override fun canAnalyze(program: Program?): Boolean {
        return program!!.executableFormat == MachoLoader.MACH_O_NAME
    }

    override fun added(prog: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        program = prog

        TODO()
    }

}
