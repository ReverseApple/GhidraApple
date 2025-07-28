package lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch

import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.actions.CreateObjCMethodThunkCmd
import lol.fairplay.ghidraapple.analysis.objectivec.GhidraTypeBuilder.Companion.OBJC_CLASS_CATEGORY
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_CLASS
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_TRAMPOLINE
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import lol.fairplay.ghidraapple.db.DataBaseLayer
import lol.fairplay.ghidraapple.db.ExternalObjectiveCClass
import lol.fairplay.ghidraapple.db.LocalObjectiveCClass
import lol.fairplay.ghidraapple.db.ObjectiveCClass

data class TypeBoundCallsiteResult(
    val typeBound: Structure?,
    val receiverParam: Varnode? = null,
)

class TypeBoundedDispatchAnalyzer :
    AbstractDispatchAnalyzer<TypeBoundCallsiteResult>(
        NAME,
        "Type Bounded Dispatch Analyzer",
        AnalyzerType.FUNCTION_SIGNATURES_ANALYZER,
        OBJC_DISPATCH_CLASS,
    ) {
    companion object {
        val PRIORITY =
            IntraProceduralImplementationAnalyzer.PRIORITY.after()
        const val NAME = "Objective-C: Type Bounded Dispatch Analyzer"
    }

    init {
        setSupportsOneTimeAnalysis()
        setDefaultEnablement(true)
    }

    override fun processResults(
        program: Program,
        result: Collection<Pair<Reference, Result<TypeBoundCallsiteResult?>>>,
        monitor: TaskMonitor,
        log: MessageLog,
    ) {
        val db = DataBaseLayer(program)
        val selectorMap = db.getSelectorMap()
        val resultMap =
            result
                .associate { (ref, result) ->
                    ref.fromAddress to result.getOrNull()?.typeBound
                }.filter { it.value != null }
        db.addTypeBounds(resultMap)

        result.forEach { (reference, typeBoundResult) ->
            val typeBound: Structure = typeBoundResult.getOrNull()?.typeBound ?: return@forEach
            val runtimeFunction: Function = program.functionManager.getFunctionAt(reference.toAddress)
            val selector =
                if (runtimeFunction.hasTag(OBJC_TRAMPOLINE)) {
                    runtimeFunction.name
                } else {
                    selectorMap[reference.fromAddress]
                } ?: return@forEach
            val cls: ObjectiveCClass = db.getClassForDataType(typeBound) ?: return@forEach
            // Technically we need to traverse the class hierarchy upwards _and downwards_ to find all possible callers
            // but for now we will just add the class that is the type bound
            val sym: Symbol =
                when (cls) {
                    is ExternalObjectiveCClass -> {
                        val cmd = CreateObjCMethodThunkCmd(cls, selector, SourceType.ANALYSIS)
                        cmd.applyTo(program)
                        cmd.function!!.symbol
                    }
                    // For local classes there should be exactly one symbol of this name already
                    is LocalObjectiveCClass -> {
                        val directMethod = program.symbolTable.getSymbols(selector, cls.namespace).singleOrNull()
                        if (directMethod == null) {
//                            cls.metaData.getImplementationForSelector(selector)!!.implAddress
                            // The class doesn't implement this method directly. It's probably from a parent
                            // TODO: search through the class hierarchy instead of giving up
                            return@forEach
                        } else {
                            directMethod
                        }
                    }
                }

            val ref =
                program.referenceManager.addMemoryReference(
                    reference.fromAddress,
                    sym.address,
                    RefType.COMPUTED_CALL,
                    SourceType.ANALYSIS,
                    0,
                )
            // TODO: This should be gated behind an option
            program.referenceManager.setPrimary(ref, true)
        }
    }

    override fun getResultForPCodeCall(
        program: Program,
        reference: Reference,
        pcodeOp: PcodeOp,
        msgLog: MessageLog,
    ): TypeBoundCallsiteResult? {
        val receiver: Varnode? = pcodeOp.inputs[1]
        val receiverType: DataType = receiver?.high?.dataType ?: return null

        val receiverBeforeCast =
            if (receiverType.name == "ID" && receiver.def?.opcode == PcodeOp.CAST) {
                val castType =
                    receiver.def.inputs[0]
                        .high.dataType
                castType
            } else {
                receiverType
            }
        if (receiverBeforeCast.categoryPath == OBJC_CLASS_CATEGORY) {
            if (receiverBeforeCast is Pointer) {
                val pointsTo = receiverBeforeCast.dataType as Structure?
                return TypeBoundCallsiteResult(pointsTo)
            }
        }

        return null
    }

    override fun filterDispatchSites(
        program: Program,
        references: List<Reference>,
    ): List<Reference> {
        // We only want the references that aren't already identified as alloced or static dispatch
        val db = DataBaseLayer(program)
        val staticReceivers = db.getAllStaticReceiverCallsites() ?: emptyMap()
        val allocedReceivers = db.getAllAllocedReceivers() ?: emptyMap()
        return references.filter { it.fromAddress !in staticReceivers.keys && it.fromAddress !in allocedReceivers.keys }
    }
}
