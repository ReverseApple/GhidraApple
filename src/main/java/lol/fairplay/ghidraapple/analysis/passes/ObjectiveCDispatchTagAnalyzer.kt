package lol.fairplay.ghidraapple.analysis.passes

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor

/**
 * This class marks important functions with special tags so that other analyzers later don't have to define what they
 * search for.
 *
 */
class ObjectiveCDispatchTagAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {
    companion object {
        const val NAME = "Objective-C Dispatch Tagging"
        const val DESCRIPTION = "Tag Objective-C dispatch functions for later analysis."
        const val OBJC_DISPATCH_SELECTOR = "OBJC_DISPATCH_SELECTOR"
        const val OBJC_TRAMPOLINE = "OBJC_TRAMPOLINE"
        const val OBJC_DISPATCH_CLASS = "OBJC_DISPATCH_CLASS"
        const val OBJC_ALLOC = "OBJC_ALLOC"
        val PRIORITY = AnalysisPriority.HIGHEST_PRIORITY
    }

    init {
        setDefaultEnablement(true)
        priority = PRIORITY
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean {
        // TODO: I don't know yet how to limit this analyzer to only Objective-C programs in a meaningful way
        return true
    }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        program.functionManager.getFunctions(set, true)
            .filter { function -> function.isExternal || function.isThunk || isPlausibleTrampoline(function) }
            .forEach { function ->
                program.functionManager.functionTagManager.allFunctionTags
                // Check if the function is in the trampoline section `__objc_stubs`
                if (isPlausibleTrampoline(function)) {
                    function.addTag(OBJC_TRAMPOLINE)
                    function.addTag(OBJC_DISPATCH_CLASS)
                }
                when (function.name) {
                    "_objc_msgSend" -> {
                        function.addTag(OBJC_DISPATCH_SELECTOR)
                        function.addTag(OBJC_DISPATCH_CLASS)
                    }
                    // The super call takes a special receiver argument
                    // so it needs to be handled differently in receiver type analysis
                    "_objc_msgSendSuper2" -> function.addTag(OBJC_DISPATCH_SELECTOR)
                    "_objc_alloc_init" -> function.addTag(OBJC_ALLOC)
                    "_objc_alloc" -> function.addTag(OBJC_ALLOC)
                    "_objc_allocWithZone" -> function.addTag(OBJC_ALLOC)
                }
            }
        return true
    }

    private fun isPlausibleTrampoline(function: Function): Boolean {
        // Look up the block that the function is in
        val block = getStubsSegment(function.program) ?: return false
        return block.contains(function.entryPoint)
    }

    private fun getStubsSegment(program: Program): MemoryBlock? = program.memory.getBlock("__objc_stubs")
}
