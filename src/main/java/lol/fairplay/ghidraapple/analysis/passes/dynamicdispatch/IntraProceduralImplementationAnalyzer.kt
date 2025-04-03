package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighParam
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType
import ghidra.util.HelpLocation
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_ALLOC
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_CLASS
import lol.fairplay.ghidraapple.analysis.passes.selectortrampoline.SelectorTrampolineAnalyzer.Companion.STUB_NAMESPACE_NAME
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass
import lol.fairplay.ghidraapple.db.DataBaseLayer
import lol.fairplay.ghidraapple.db.Selector

// typealias CallsiteResult = Pair<Address, Boolean>

data class CallsiteResult(
    val classAddr: Address?,
    val typeBound: DataType?,
    val isStatic: Boolean?,
    val selector: Selector?,
    val followedInit: Boolean = false,
    val followedShared: Boolean = false,
)

/**
 *
 * In the future this should provide an alternative to the [OCSelectorAnalyzer]
 */
class IntraProceduralImplementationAnalyzer :
    AbstractDispatchAnalyzer<CallsiteResult>(
        NAME,
        "A dynamic dispatch analysis that attempts to find receiver type information for Objective-C dispatch calls",
        AnalyzerType.INSTRUCTION_ANALYZER, OBJC_DISPATCH_CLASS) {
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

    override fun registerOptions(options: Options, program: Program) {
        options.registerOption(
            "Include constructor heuristic",
            true,
            null as HelpLocation?,
            "Methods starting with 'init' are treated as constructors, and their return value is treated as their receiver argument"
        )

        options.registerOption(
            "Include shared* heuristic",
            true,
            null as HelpLocation?,
            "Methods starting with the name shared* are treated as returning an instance of their static class argument"
        )

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

            val classCache = mutableMapOf<Address, OCClass?>()
            val classParser = StructureParsing(program)
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
                        callsiteResult.classAddr.isConstantAddress || callsiteResult.classAddr.isMemoryAddress -> {
                            val classModel = classCache.computeIfAbsent(callsiteResult.classAddr) { classParser.parseClass(it)}

                            val classDataAddress: Address? = kotlin.runCatching {
                                db.getClassForAddress(callsiteResult.classAddr).classStructLocation
                            }.getOrElse {
                                log.appendMsg("Error while processing callsite at ${ref.fromAddress}: ${it.message}")
                                null
                            }
                            if (callsiteResult.isStatic == true) {
                                staticDispatchTable[ref.fromAddress] = classDataAddress
                                callsiteResult.selector?.let { selector ->
                                    classModel?.baseClassMethods?.singleOrNull { it.name == selector }
                                }?.let { staticMethodImpl ->
                                    ApplyDynamicDispatchTargetRewriteCmd(ref.fromAddress, staticMethodImpl, SourceType.ANALYSIS)
                                        .applyTo(program)
                                }


                            } else {
                                callsiteResult.selector?.let { selector ->
                                    classModel?.getImplementationForSelector(selector)
                                }?.let {
                                    ApplyDynamicDispatchTargetRewriteCmd(ref.fromAddress, it, SourceType.ANALYSIS)
                                        .applyTo(program)
                                }
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
                                if (db.isTypeInternal(structType) && callsiteResult.selector != null) {
                                    // TODO: This is unsound and should be gated behind an option
                                    val classData = db.getClassForDataType(structType)
                                    classData?.metadata?.getImplementationForSelector(callsiteResult.selector)
                                        ?.let {
                                            ApplyDynamicDispatchTargetRewriteCmd(ref.fromAddress, it, SourceType.ANALYSIS)
                                                .applyTo(program)
                                        }
                                }
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
     *
     * Optional heuristics allow passing through methods like `sharedInstance` and `init*`
     * to find the type they were provided with.
     */
    override fun getResultForPCodeCall(
        program: Program,
        reference: Reference,
        pcodeOp: PcodeOp,
        msgLog: MessageLog,
    ): CallsiteResult {
        var receiver: Varnode? = pcodeOp.inputs[1]
        var isStatic = true
        var typeBound = receiver?.high?.dataType
        var followedInit = false
        var followedShared = false
        if (typeBound != null && typeBound is Pointer) {
            if (typeBound.name != "undefined8" && typeBound.name != "ID") {
                Msg.info(this, "Type bound at ${pcodeOp.seqnum.target}: $typeBound")
            }
        }
        // Sometimes we get a constant, sometimes a RAM address?
        while (receiver != null && !(receiver.isConstant || receiver.isAddress)) {

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
                                followedInit = true
                                definingOp.inputs[1]
                            }
                            func.name.startsWith("shared") -> {
                                isStatic = false
                                followedShared = true
                                definingOp.inputs[1]
                            }
                            func.name.startsWith("alloc") -> {
                                // 1000eb7b8
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
//        val selector = pcodeOp.inputs[2].constantValue?.let { Selector(it.toInt()) }\
        val dispatchFunction = program.functionManager.getFunctionAt(reference.toAddress)
        val selector = if (dispatchFunction.parentNamespace.name == STUB_NAMESPACE_NAME) {
            dispatchFunction.name
        } else {
            // TODO: Get the selector from the second argument in x1
            null
        }
        val result = CallsiteResult(receiver?.address, typeBound, isStatic, selector, followedInit, followedShared)
        return result

    }
}
