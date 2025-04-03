package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer
import lol.fairplay.ghidraapple.analysis.utilities.getConstantFromVarNode
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import lol.fairplay.ghidraapple.db.DataBaseLayer
import kotlin.jvm.optionals.getOrNull

/**
 * Uses the tags from [ObjectiveCDispatchTagAnalyzer] to analyze the dispatch of Objective-C selectors.
 * The results are stored in a dedicates PropertyMapManager map that associates the selector string with each callsite
 *
 * This implies limitations: We only store one or no selector per callsite. This is fine for most cases, but not for
 * all. In the future we will need to store more complex information for a callsite, but for now this PoC is sufficient
 *
 */
class OCSelectorAnalyzer :
    AbstractDispatchAnalyzer<String>(
        NAME,
        DESCRIPTION,
        AnalyzerType.INSTRUCTION_ANALYZER,
        ObjectiveCDispatchTagAnalyzer.OBJC_DISPATCH_SELECTOR,
    ) {
    companion object {
        private const val NAME = "Objective-C: Selector Analysis"
        private const val DESCRIPTION = "For all calls to functions tagged with OBJC_DISPATCH_SELECTOR"
        private val PRIORITY = ObjectiveCDispatchTagAnalyzer.PRIORITY.after().after()
    }

    init {
        setDefaultEnablement(true)
        priority = PRIORITY
        setSupportsOneTimeAnalysis()
    }

    /**
     * Store the results into a dedicated UserPropertyMap
     */
    override fun processResults(
        program: Program,
        result: Collection<Pair<Reference, Result<String?>>>,
        monitor: TaskMonitor,
        log: MessageLog,
    ) {
        DataBaseLayer(program).addSelectors(
            result.associate { (reference, selector) -> reference.fromAddress to selector.getOrNull() },
        )
    }

    override fun prepare(
        program: Program,
        functionsToAnalyze: List<Function>,
    ) {
        program.withTransaction<Exception>("Setup msgSend signatures") {
            functionsToAnalyze.forEach { func ->
                val id = program.dataTypeManager.getDataType("/_objc2_/ID")
                val sel = program.dataTypeManager.getDataType("/_objc2_/SEL")
                if (func.signature.arguments.isEmpty()) {
                    func.addParameter(ParameterImpl("cls", id, program), SourceType.IMPORTED)
                    func.addParameter(ParameterImpl("sel", sel, program), SourceType.IMPORTED)
                    func.setReturnType(id, SourceType.IMPORTED)
                }
            }
        }
        // ensure that the functions all have at least two arguments, the second one being the selector reference
    }

    /**
     * Extract the selector as a string from the second argument of the call
     */
    override fun getResultForPCodeCall(
        program: Program,
        reference: Reference,
        pcodeOp: PcodeOp,
        msgLog: MessageLog,
    ): String? {
        val selector = pcodeOp.getInput(2)
        if (selector == null) {
            msgLog.appendMsg("No selector argument found in call at ${pcodeOp.seqnum}")
            return null
        }
        val r = getConstantFromVarNode(selector).getOrNull()
        // We now have the constant address of the selector. We need to translate this into a proper address
        val selectorAddr = r?.toDefaultAddressSpace(program)
        // Now we need the string at that address
        selectorAddr?.let { addr ->
            program.listing.getDataAt(addr)?.value?.let {
                return it as? String
            }
        }
        return null
    }
}
