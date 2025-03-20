package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighParam
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.Reference
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_ALLOC
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_CLASS
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import lol.fairplay.ghidraapple.db.DataBaseLayer
import lol.fairplay.ghidraapple.db.Selector

// typealias CallsiteResult = Pair<Address, Boolean>

data class CallsiteResult(
    val classAddr: Address?,
    val typeBound: DataType?,
    val isStatic: Boolean?,
    val selector: Selector?
)

/**
 *
 * In the future this should provide an alternative to the [OCSelectorAnalyzer]
 */
class IntraProceduralImplementationAnalyzer :
    AbstractDispatchAnalyzer<CallsiteResult>(NAME, "", AnalyzerType.INSTRUCTION_ANALYZER, OBJC_DISPATCH_CLASS) {
    companion object {
        val PRIORITY = AnalysisPriority.DATA_TYPE_PROPOGATION.after().after()
        const val NAME = "Objective-C: Intraprocedural Dispatch Analysis"
    }

    init {
        priority = PRIORITY
//        setPrototype()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun processResults(
        program: Program,
        result: Collection<Pair<Reference, Result<CallsiteResult?>>>,
        monitor: TaskMonitor,
        log: MessageLog,
    ) {
        program.withTransaction<Exception>("Process dispatch results") {
            val db = DataBaseLayer(program)
            // Group the results
            val allocedDispatchInfo = mutableMapOf<Address, Address?>()
            val staticDispatchTable = mutableMapOf<Address, Address?>()
            val typeBoundsTable = mutableMapOf<Address, DataType?>()
            val paramDispatchTable = mutableMapOf<Address, Address?>()
            monitor.maximum = result.size.toLong()
            result
                .asSequence()
                .onEach { monitor.incrementProgress() }
                // Unpack the Result type to get the actual value
                .map{ (callsite, result) -> callsite to result.getOrNull() }
                // Filter out null results
                .mapNotNull { (reference, result) -> if (result != null) reference to result else null }
                // Filter only to constant addresses
//                .filter { (_, callsiteResult) -> callsiteResult.classAddr?.isConstantAddress == true }
                // Translate the const:0x4000 addresses to default:0x4000 addresses
//                .map { (ref, callsiteResult) -> ref to callsiteResult }
                // Add to property maps
                .forEach { (ref, callsiteResult) ->
                    when {
                        callsiteResult.classAddr == null -> {}
                        callsiteResult.classAddr.isConstantAddress -> {
                            val classDataAddress: Address? = kotlin.runCatching {
                                db.getClassForAddress(callsiteResult.classAddr).classStructLocation
                            }.getOrElse {
                                log.appendMsg("Error while processing callsite at ${ref.fromAddress}: ${it.message}")
                                null
                            }
                            if (callsiteResult.isStatic == true) {
                                staticDispatchTable[ref.fromAddress] = classDataAddress
                            } else {
                                allocedDispatchInfo[ref.fromAddress] = classDataAddress
                            }
                        }
                        callsiteResult.classAddr.isRegisterAddress -> {
                            paramDispatchTable[ref.fromAddress] = callsiteResult.classAddr
                        }
                    }

                    when (val structType = (callsiteResult.typeBound as? Pointer)?.dataType) {
                        is Structure -> {
                            if (structType.name != "class_t") {
                                typeBoundsTable[ref.fromAddress] = structType
                            }
                        }
                        else -> {}
                    }
                }
            db.addStaticReceivers(staticDispatchTable)
            db.addTypeBounds(typeBoundsTable)
            db.addAllocedReceivers(allocedDispatchInfo)
            db.addParamReceivers(paramDispatchTable)
        }
    }

    /**
     * Walk the SSA form backwards to find either a function tagged with
     * [ObjectiveCDispatchTagAnalyzer.Companion.OBJC_ALLOC]
     * or a static reference to a class.
     */
    override fun getResultForPCodeCall(
        program: Program,
        pcodeOp: PcodeOp,
        msgLog: MessageLog,
    ): CallsiteResult {
        var receiver: Varnode? = pcodeOp.inputs[1]
        var isStatic = true
        var typeBound = receiver?.high?.dataType
        if (typeBound != null && typeBound is Pointer) {
            if (typeBound.name != "undefined8" && typeBound.name != "ID") {
                Msg.info(this, "Type bound at ${pcodeOp.seqnum.target}: $typeBound")
            }
        }
        while (receiver != null && !receiver.isConstant) {
            val definingOp = receiver.def
            if (definingOp == null) {
                isStatic = false
                if (receiver.high is HighParam) {
                    // Receiver could be directly traced back to a function argument
                    // we should track those separately, for now we ignore them
                    typeBound = receiver.high.dataType
                } else {
                    msgLog.appendMsg("No defining operation found for receiver at ${receiver.address}")
                }
                break
            }
            receiver =
                when (definingOp.opcode) {
                    PcodeOp.CAST -> {
                        typeBound = definingOp.inputs[0].high?.dataType
                        definingOp.inputs[0]
                    }
                    PcodeOp.COPY -> definingOp.inputs[0]
                    PcodeOp.PTRSUB -> definingOp.inputs.first { !(it.isConstant && it.offset == 0L) }
                    PcodeOp.LOAD -> {
//                        msgLog.appendMsg("Load operation in receiver analysis. Skipping")
                        null
                    }
                    PcodeOp.MULTIEQUAL -> {
//                        msgLog.appendMsg("Multiequal operation in receiver analysis. Skipping")
                        null
                    }
                    PcodeOp.INDIRECT -> definingOp.inputs[0]
                    PcodeOp.CALL -> {
                        // Get the function being called
                        val func = program.functionManager.getFunctionAt(definingOp.inputs[0].address)
                        when {
                            func.hasTag(OBJC_ALLOC) -> {
                                isStatic = false
                                definingOp.inputs[1]
                            }
                            func.name.startsWith("init") -> {
                                // Constructor heuristic
                                isStatic = false
                                definingOp.inputs[1]
                            }
                            else -> {
//                                msgLog.appendMsg("Call operation in receiver analysis. Skipping")
                                null
                            }
                        }
                    }
                    else -> {
                        msgLog.appendMsg("Unknown opcode ${definingOp.mnemonic} encountered at ${definingOp.seqnum.target}")
                        null
                    }
                }
        }
        val result = CallsiteResult(receiver?.address, typeBound, isStatic, null)
        return result
    }
}
