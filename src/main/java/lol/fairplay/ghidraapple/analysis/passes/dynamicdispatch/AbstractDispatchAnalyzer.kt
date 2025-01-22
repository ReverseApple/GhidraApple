package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.decompiler.DecompileResults
import ghidra.app.decompiler.parallel.DecompileConfigurer
import ghidra.app.decompiler.parallel.DecompilerCallback
import ghidra.app.decompiler.parallel.ParallelDecompiler
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.Reference
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.getFunctionsWithTag

/**
 * Abstract Analyzer that generalizes over the pattern:
 * 1. Find all callsites to certain functions (expressed via tags)
 * 2. Group the callsites into functions that contain them
 * 3. Decompile the functions (with parallel decompilers)
 * 4. Analyze the callsites in the decompiled functions to get the [CALLSITE_RESULT] for each callsite
 * 5. Merge the results into a useful form
 * 6. Apply these results to the program
 */
abstract class AbstractDispatchAnalyzer<CALLSITE_RESULT>(
    name: String,
    description: String,
    analyzerType: AnalyzerType,
    private val tag: String,
) : AbstractAnalyzer(name, description, analyzerType) {
    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        val dispatchFunctions: Collection<Function> = program.functionManager.getFunctionsWithTag(tag)

        val dispatchSites: Collection<Reference> =
            dispatchFunctions
                .flatMap { program.referenceManager.getReferencesTo(it.entryPoint) }
                .filter { it.referenceType.isCall }
                .filter { it.fromAddress in set }

        // Group dispatch sites according to containing function
        val dispatchSitesByFunction =
            dispatchSites.groupBy { program.functionManager.getFunctionContaining(it.fromAddress) }

        dispatchSitesByFunction[null]?.forEach {
            log.appendMsg("Dispatch site $it could not be associated with function. Skipping")
        }
        val callback =
            object : DecompilerCallback<Map<Reference, CALLSITE_RESULT?>>(program, configureDecompiler()) {
                override fun process(
                    results: DecompileResults,
                    monitor: TaskMonitor,
                ): Map<Reference, CALLSITE_RESULT?> {
                    monitor.incrementProgress(1)
                    return decompilerCallback(results, dispatchSitesByFunction[results.function]!!, monitor)
                }
            }
        monitor.maximum = dispatchSitesByFunction.size.toLong()
        val results: List<Map<Reference, CALLSITE_RESULT?>> =
            ParallelDecompiler.decompileFunctions(
                callback,
                dispatchSitesByFunction.keys.filterNotNull(),
                monitor,
            )
        callback.dispose()

        // Turn results into a flat list of Pair<Reference, CALLSITE_RESULT>
        processResults(program, results.flatMap { functionResult -> functionResult.entries.map { it.key to it.value } })
        return true
    }

    /**
     * configures the decompiler to be used for analysis later
     * This can be overridden to provide custom configuration
     * but the default one is probably fine for most cases
     */
    open fun configureDecompiler(): DecompileConfigurer =
        DecompileConfigurer { decompiler: DecompInterface ->
            decompiler.simplificationStyle = "normalize"
            decompiler.toggleSyntaxTree(true)
            decompiler.toggleCCode(false)
            decompiler.setOptions(
                DecompileOptions().apply {
                    this.isRespectReadOnly = true
                },
            )
        }

    /**
     * Used for preparation before the analysis starts
     * Examples are making sure that the type signatures for the functions of interest are set up correctly
     * so that the decompiler works with the correct assumptions about their arguments
     */
    open fun prepare(
        program: Program,
        functionsToAnalyze: List<Function>,
    ) {
    }

    abstract fun processResults(
        program: Program,
        result: Collection<Pair<Reference, CALLSITE_RESULT?>>,
    )

    protected fun decompilerCallback(
        results: DecompileResults,
        references: Collection<Reference>,
        monitor: TaskMonitor,
    ): Map<Reference, CALLSITE_RESULT?> =
        getCallOps(results, references, monitor)
            .mapValues { (_, pcodeOp) -> getResultForPCodeCall(results.highFunction.function.program, pcodeOp) }

    /**
     * Helper function to get the PcodeOps for the references
     */
    private fun getCallOps(
        results: DecompileResults,
        references: Collection<Reference>,
        monitor: TaskMonitor,
    ): Map<Reference, PcodeOp> {
        val addressSet = references.map { it.fromAddress }.toSet()
        return results.highFunction.pcodeOps
            .asSequence()
            .filter { it.opcode == PcodeOp.CALL || it.opcode == PcodeOp.CALLIND }
            .filter { it.seqnum.target in addressSet }
            .associateBy { references.first { ref -> ref.fromAddress == it.seqnum.target } }
    }

    abstract fun getResultForPCodeCall(
        program: Program,
        pcodeOp: PcodeOp,
    ): CALLSITE_RESULT?
}
