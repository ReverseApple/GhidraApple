package lol.fairplay.ghidraapple.analysis.passes.blocks

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.OptionType
import ghidra.framework.options.Options
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

        private const val CONST_SECTION_ITERATE_OPTION_NAME = "Iterate over `__const` sections for pointers"
        private const val CONST_SECTION_ITERATE_OPTION_DESCRIPTION =
            "Whether or not to iterate the `__const` sections of the main binary to look for pointers to the " +
                "global block symbol that all global blocks start with. This is often unnecessary, but can be " +
                "useful in cases where some such pointers are not known to Ghidra's reference manager."
    }

    init {
        priority = AnalysisPriority.DATA_TYPE_PROPOGATION
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun registerOptions(
        options: Options,
        program: Program,
    ) {
        options.registerOption(
            CONST_SECTION_ITERATE_OPTION_NAME,
            OptionType.BOOLEAN_TYPE,
            false,
            null,
            CONST_SECTION_ITERATE_OPTION_DESCRIPTION,
        )
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
        val shouldIterateOverConstSections =
            program
                .getOptions(Program.ANALYSIS_PROPERTIES)
                .getOptions(ObjectiveCGlobalBlockAnalyzer.NAME)
                .getBoolean(CONST_SECTION_ITERATE_OPTION_NAME, false)
        program
            .let { it.getReferencesToSymbol("__NSConcreteGlobalBlock") + it.getReferencesToSymbol("__NSGlobalBlock__") }
            .filter { set.contains(it.fromAddress) }
            .filter { it.referenceType == RefType.DATA }
            .filter { program.memory.getBlock(it.fromAddress)?.name == "__const" }
            .map { it.fromAddress }
            .toSet()
            .let { referenceAddresses ->
                // TODO: We should rename this option if the behavior of [FindGlobalBlockSymbolPointers] ever changes.
                if (shouldIterateOverConstSections) {
                    FindGlobalBlockSymbolPointers(program).let {
                        it.run(TaskMonitor.DUMMY)
                        // Return the combined addresses.
                        referenceAddresses + it.addresses
                    }
                } else {
                    // Otherwise, return them as-is.
                    referenceAddresses
                }
            }.forEach {
                MarkNSConcreteGlobalBlock(it).applyTo(program)
            }
        return true
    }
}
