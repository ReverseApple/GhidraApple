package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.decompiler.parallel.DecompileConfigurer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighParam
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType
import ghidra.util.HelpLocation
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.CreateObjCMethodThunkCmd
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_ALLOC
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_CLASS
import lol.fairplay.ghidraapple.analysis.passes.selectortrampoline.SelectorTrampolineAnalyzer.Companion.STUB_NAMESPACE_NAME
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import lol.fairplay.ghidraapple.db.DataBaseLayer
import lol.fairplay.ghidraapple.db.ExternalObjectiveCClass
import lol.fairplay.ghidraapple.db.LocalObjectiveCClass
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
        AnalyzerType.INSTRUCTION_ANALYZER,
        OBJC_DISPATCH_CLASS,
    ) {
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

    override fun registerOptions(
        options: Options,
        program: Program,
    ) {
        options.registerOption(
            "Include constructor heuristic",
            true,
            null as HelpLocation?,
            "Methods starting with 'init' are treated as constructors, and their return value is treated as their receiver argument",
        )

        options.registerOption(
            "Include shared* heuristic",
            true,
            null as HelpLocation?,
            "Methods starting with the name shared* are treated as returning an instance of their static class argument",
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
            monitor.maximum = result.size.toLong()
            val data: Sequence<Pair<Reference, CallsiteResult>> =
                result
                    .asSequence()
                    .onEach { monitor.incrementProgress() }
                    // Unpack the Result type to get the actual value
                    .map { (callsite, result) -> callsite to result.getOrNull() }
                    // Filter out null results
                    .mapNotNull { (reference, result) -> if (result != null) reference to result else null }

            // Sort out all the cases where we did not find any class address
            val (classPtrFound, noClassPtrFound) = data.partition { (_, callsiteResult) -> callsiteResult.classAddr != null }

            val (constantClassPtr, dynamicReceivers) =
                classPtrFound.partition { (_, refinedCallsiteResult) ->
                    with(
                        refinedCallsiteResult.classAddr!!,
                    ) { isConstantAddress || isMemoryAddress }
                }

//            val typeBoundReceivers =
//                dynamicReceivers.filter { (_, refinedCallsiteResult) -> refinedCallsiteResult.typeBound != null }

            val (allocedClassPtr, staticClassPtr) =
                constantClassPtr.partition { (_, refinedCallsiteResult) ->
                    refinedCallsiteResult.isStatic == false
                }

            staticClassPtr.apply {
                db.addStaticReceivers(this.associate { (ref, refinedCallsite) -> ref.fromAddress to refinedCallsite.classAddr })
                this.forEach { (ref, refinedCallsite) ->
                    val selector = refinedCallsite.selector ?: return@forEach

                    val classData = db.getClassForAddress(refinedCallsite.classAddr!!) ?: return@forEach
                    // Check if the class is internal or external
                    // If it is external, the implementation we are looking for is definitely external
                    // If it is internal, the implementation might be internal or external

                    when (classData) {
                        is LocalObjectiveCClass -> {
                            val internalImpl = classData.metaData.getStaticMethodForSelector(selector)
                            if (internalImpl != null) {
                                ApplyDynamicDispatchTargetRewriteCmd
                                    .toMethod(
                                        program,
                                        internalImpl,
                                        ref.fromAddress,
                                        SourceType.ANALYSIS,
                                    ).applyTo(program)
                            } else {
                                // TODO: We need to create a thunk for the selector on the first class in the hierarchy
                                // which is outside the current binary
                                log.appendMsg("No implementation found for selector '$selector' in class '${classData.name}'")
                            }
                        }

                        is ExternalObjectiveCClass -> {
                            // We need to create a thunk for the selector
                            val thunkCmd =
                                CreateObjCMethodThunkCmd(classData, selector).also {
                                    it.applyTo(program)
                                }
                            ApplyDynamicDispatchTargetRewriteCmd(
                                ref.fromAddress,
                                thunkCmd.function!!,
                                SourceType.ANALYSIS,
                            ).applyTo(program)
                        }
                    }
                }
            }

            allocedClassPtr.apply {
                db.addAllocedReceivers(this.associate { (ref, refinedCallsite) -> ref.fromAddress to refinedCallsite.classAddr })
                this.forEach { (ref, refinedCallsite) ->
                    val selector = refinedCallsite.selector ?: return@forEach
                    val classData = db.getClassForAddress(refinedCallsite.classAddr!!) ?: return@forEach
                    // Check if the class is internal or external
                    // If it is external, the implementation we are looking for is definitely external
                    // If it is internal, the implementation might be internal or external
                    when (classData) {
                        is LocalObjectiveCClass -> {
                            val internalImpl = classData.metaData.getImplementationForSelector(selector)
                            if (internalImpl != null) {
                                ApplyDynamicDispatchTargetRewriteCmd
                                    .toMethod(
                                        program,
                                        internalImpl,
                                        ref.fromAddress,
                                        SourceType.ANALYSIS,
                                    ).applyTo(program)
                            } else {
                                // TODO: We need to create a thunk for the selector on the first class in the hierarchy
                                // which is outside the current binary
                                log.appendMsg("No implementation found for selector '$selector' in class '${classData.name}'")
                            }
                        }

                        is ExternalObjectiveCClass -> {
                            // We need to create a thunk for the selector
                            val thunkCmd =
                                CreateObjCMethodThunkCmd(classData, selector).also {
                                    it.applyTo(program)
                                }
                            ApplyDynamicDispatchTargetRewriteCmd(
                                ref.fromAddress,
                                thunkCmd.function!!,
                                SourceType.ANALYSIS,
                            ).applyTo(program)
                        }
                    }
                }
            }
        }
    }

    override fun configureDecompiler(): DecompileConfigurer =
        DecompileConfigurer { decompiler: DecompInterface ->
            // We don't use the data type inference for this analyzer, and we want the constant prop
            // provided by normalize
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
//        var typeBound = receiver?.high?.dataType
        var followedInit = false
        var followedShared = false
//        if (typeBound != null && typeBound is Pointer) {
//            if (typeBound.name != "undefined8" && typeBound.name != "ID") {
//                Msg.info(this, "Type bound at ${pcodeOp.seqnum.target}: $typeBound")
//            }
//        }
        // Sometimes we get a constant, sometimes a RAM address?
        while (receiver != null && !(receiver.isConstant || receiver.isAddress)) {
            val definingOp = receiver.def
            if (definingOp == null) {
                isStatic = false
                if (receiver.high is HighParam) {
                    // Receiver could be directly traced back to a function argument
                    // we should track those separately, for now we ignore them
//                    typeBound = receiver.high.dataType
                } else {
                    msgLog.appendMsg("No defining operation found for receiver at ${receiver.address}")
                }
                break
            }
            receiver =
                when (definingOp.opcode) {
                    PcodeOp.CAST -> {
//                        typeBound = definingOp.inputs[0].high?.dataType
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
                            func.name == "new" -> {
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
        val selector =
            if (dispatchFunction.parentNamespace.name == STUB_NAMESPACE_NAME) {
                dispatchFunction.name
            } else {
                // TODO: Get the selector from the second argument in x1
//                getSelectorFromVarNode(pcodeOp.inputs[2])
                null
            }
        val result = CallsiteResult(receiver?.address, null, isStatic, selector, followedInit, followedShared)
        return result
    }

//    private fun getSelectorFromVarNode(varNode: Varnode): Selector? {
//        return varNode.constantValue?.let { Selector(it.toInt()) }
//    }
}
