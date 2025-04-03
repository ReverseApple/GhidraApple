package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.decompiler.DecompileOptions
import ghidra.app.decompiler.parallel.DecompileConfigurer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch.AbstractDispatchAnalyzer
import lol.fairplay.ghidraapple.analysis.utilities.addCollection
import lol.fairplay.ghidraapple.analysis.utilities.getConstantFromVarNode
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import lol.fairplay.ghidraapple.db.DataBaseLayer
import kotlin.jvm.optionals.getOrNull

class OCTypeInjectorAnalyzer :
    AbstractDispatchAnalyzer<Address>(
        NAME,
        DESCRIPTION,
        AnalyzerType.INSTRUCTION_ANALYZER,
        ObjectiveCDispatchTagAnalyzer.OBJC_ALLOC,
    ) {
    companion object {
        const val NAME = "Objective-C Type Injection"
        private const val DESCRIPTION = ""

        // This has to run before the data type propagation (but not earlier), otherwise not all alloc calls are found?
        private val PRIORITY = AnalysisPriority.DATA_TYPE_PROPOGATION.before()
        const val ALLOC_DATA = "AllocData"
    }

    override fun canAnalyze(program: Program): Boolean {
        return super.canAnalyze(program)
    }

    init {
        priority = PRIORITY
        setPrototype()
        setSupportsOneTimeAnalysis()
    }

    override fun prepare(
        program: Program,
        functionsToAnalyze: List<Function>,
    ) {
        program.withTransaction<Exception>("Setup alloc signatures") {
            functionsToAnalyze.forEach { func ->
                val id = program.dataTypeManager.getDataType("/_objc2_/ID")
                if (func.signature.arguments.isEmpty()) {
                    func.addParameter(ParameterImpl("cls", id, program), SourceType.IMPORTED)
                    func.setReturnType(id, SourceType.IMPORTED)
                } else if (func.signature.arguments[0].dataType.length != 8) {
                    func.signature.arguments[0].dataType = id
                    func.setReturnType(id, SourceType.IMPORTED)
                }
            }
        }
    }

    override fun getResultForPCodeCall(
        program: Program,
        reference: Reference,
        pcodeOp: PcodeOp,
        msgLog: MessageLog,
    ): Address? {
        val clsVarNode = pcodeOp.getInput(1)
        if (clsVarNode == null) {
            msgLog.appendMsg("Alloc call without argument at ${pcodeOp.seqnum.target}")
            return null
        }
        val r = getConstantFromVarNode(clsVarNode).getOrNull()
        val classAddr = r?.toDefaultAddressSpace(program)
        return classAddr
    }

    override fun processResults(
        program: Program,
        result: Collection<Pair<Reference, Result<Address?>>>,
        monitor: TaskMonitor,
        log: MessageLog,
    ) {
        val dataBaseLayer = DataBaseLayer(program)

        val resultsAsClass =
            result.map {
                    (ref, addr) ->
                ref.fromAddress to
                    addr.getOrNull()?.let {
                        dataBaseLayer.getClassForAddress(it)
                    }
            }
        val propMap =
            program.usrPropertyManager.getLongPropertyMap(ALLOC_DATA) ?: program.usrPropertyManager.createLongPropertyMap(
                ALLOC_DATA,
            )
        propMap.addCollection(resultsAsClass.map { (callsite, cls) -> callsite to cls?.classStructLocation?.offset })
        resultsAsClass.forEach { (callsite, cls) ->
            if (cls == null) {
                log.appendMsg(this.toString(), "Failed to find alloced symbol address at $callsite")
            } else {
                ApplyAllocTypeOverrideCommand(
                    callsite,
                    cls.classPointerType,
                ).applyTo(program)
            }
        }
    }

    override fun configureDecompiler(): DecompileConfigurer =
        // We only need a simple backward slice to find the class address, so no need to run type inference on the
        // function. `normalize` should be sufficient
        DecompileConfigurer { decompiler ->
            decompiler.setSimplificationStyle("normalize")
            decompiler.toggleCCode(false)
            decompiler.setOptions(
                DecompileOptions().apply { this.isRespectReadOnly = true },
            )
        }

    private fun generateFunctionSignatureForType(type: DataType): FunctionSignature {
        val fsig = FunctionDefinitionDataType("tmpname")
        fsig.returnType = type
        fsig.setArguments(ParameterDefinitionImpl("cls", type, null))
        return fsig
    }
}
