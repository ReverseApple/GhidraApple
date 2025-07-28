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
import ghidra.framework.cmd.Command
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.Reference
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.getFunctionsWithTag

/**
 * The Abstract Analyzer that generalizes over the pattern:
 * 1. Find all callsites to certain functions (expressed via tags)
 * 2. Group the callsites into functions that contain them
 * 3. Decompile the functions (with parallel decompilers)
 * 4. Analyze the callsites in the decompiled functions to get the [CALLSITE_RESULT] for each callsite
 * 5. Merge the results into a useful form
 * 6. Apply these results to the program
 *
 *
 * This is inefficient, because each subclass of an AbstractDispatchAnalyzer
 * will decompile the same function multiple times, but it allows rapid prototyping of new capabilities
 */
abstract class AbstractDispatchAnalyzer<CALLSITE_RESULT>(
    name: String,
    description: String,
    analyzerType: AnalyzerType,
    private val tag: String,
) : AbstractAnalyzer(name, description, analyzerType) {
    /**
     * TODO: we need a general way to limit the analysis to "Objective-C" programs, which will be the reasonable
     * limitation shared among all sub-classes of this analyzers
     *
     * Specific analyses can still override this method to provide more specific limitations
     */
    override fun canAnalyze(program: Program): Boolean = true

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        val dispatchFunctions: Collection<Function> = program.functionManager.getFunctionsWithTag(tag)

        if (dispatchFunctions.isEmpty()) {
            log.appendMsg(this.toString(), "No functions found with tag: $tag")
            return false
        }
        val dispatchSites: Collection<Reference> =
            dispatchFunctions
                .flatMap { program.referenceManager.getReferencesTo(it.entryPoint) }
                .filter { it.referenceType.isCall }
                .filter { it.fromAddress in set }
                .let { filterDispatchSites(program, it) }

        // Group dispatch sites according to containing function
        val dispatchSitesByFunction =
            dispatchSites.groupBy { program.functionManager.getFunctionContaining(it.fromAddress) }

        dispatchSitesByFunction[null]?.forEach {
            log.appendMsg("Dispatch site $it could not be associated with function. Skipping")
        }
        val callback =
            object : DecompilerCallback<Map<Reference, Result<CALLSITE_RESULT?>>>(program, configureDecompiler()) {
                override fun process(
                    results: DecompileResults,
                    monitor: TaskMonitor,
                ): Map<Reference, Result<CALLSITE_RESULT?>> {
                    monitor.incrementProgress(1)
                    return decompilerCallback(results, dispatchSitesByFunction[results.function]!!, monitor, log)
                }
            }
        monitor.maximum = dispatchSitesByFunction.size.toLong()
        val results: List<Map<Reference, Result<CALLSITE_RESULT?>>> =
            ParallelDecompiler.decompileFunctions(
                callback,
                dispatchSitesByFunction.keys.filterNotNull(),
                monitor,
            )
        callback.dispose()
        if (monitor.isCancelled) {
            log.appendMsg("Decompilation cancelled")
            return false
        }
        monitor.message = "Finished Decompilation"

        val flatResults = results.flatMap { functionResult -> functionResult.entries.map { it.key to it.value } }
        flatResults.filter { (_, result) -> result.isFailure }.forEach { (callsite, result) ->
            log.appendMsg("Failed to analyze callsite at ${callsite.fromAddress}: ${result.exceptionOrNull()?.message}")
        }

        monitor.message = "Processing results of ${this.name}"
        // Turn results into a flat list of Pair<Reference, CALLSITE_RESULT>
        processResults(
            program,
            flatResults,
            monitor,
            log,
        )
        return true
    }

    open fun filterDispatchSites(
        program: Program,
        references: List<Reference>,
    ): List<Reference> = references

    /**
     * configures the decompiler to be used for analysis later
     * This can be overridden to provide custom configuration
     * but the default one is probably fine for most cases
     * By default we use the highest level of P-Code simplification with full type analysis
     *
     * If an analysis requires only basic dataflow it can override this method
     */
    open fun configureDecompiler(): DecompileConfigurer =
        DecompileConfigurer { decompiler: DecompInterface ->
            decompiler.simplificationStyle = "decompile"
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

    /**
     * This function takes the results that the analysis computed for all callsites and "processes" them
     * This typically means at least one of (or both):
     * - Store the data in some table via the [PropertyMapManager] from [Program.getUsrPropertyManager]
     * - instantiate a [Command] for all or for each and apply to the [Program]
     */
    abstract fun processResults(
        program: Program,
        result: Collection<Pair<Reference, Result<CALLSITE_RESULT?>>>,
        monitor: TaskMonitor,
        log: MessageLog,
    )

    protected fun decompilerCallback(
        results: DecompileResults,
        references: Collection<Reference>,
        monitor: TaskMonitor,
        msgLog: MessageLog,
    ): Map<Reference, Result<CALLSITE_RESULT?>> =
        getCallOps(results, references, monitor, msgLog)
            .mapValues { (ref, pcodeOp) ->
                runCatching {
                    getResultForPCodeCall(
                        results.highFunction.function.program,
                        ref,
                        pcodeOp,
                        msgLog,
                    )
                }
            }

    /**
     * Helper function to get the PcodeOps for the references
     */
    private fun getCallOps(
        results: DecompileResults,
        references: Collection<Reference>,
        monitor: TaskMonitor,
        msgLog: MessageLog,
    ): Map<Reference, PcodeOp> {
        val addressSet = references.map { it.fromAddress }.toSet()
        if (results.highFunction == null) {
            msgLog.appendMsg("Failed to decompile function ${results.function} containing callsites $addressSet")
            return emptyMap()
        }
        return results.highFunction.pcodeOps
            .asSequence()
            .filter { it.opcode == PcodeOp.CALL || it.opcode == PcodeOp.CALLIND }
            .filter { it.seqnum.target in addressSet }
            .associateBy { references.first { ref -> ref.fromAddress == it.seqnum.target } }
    }

    abstract fun getResultForPCodeCall(
        program: Program,
        reference: Reference,
        pcodeOp: PcodeOp,
        msgLog: MessageLog,
    ): CALLSITE_RESULT?
}
