package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.decompiler.DecompileOptions
import ghidra.app.decompiler.parallel.DecompileConfigurer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
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
import ghidra.program.model.symbol.Symbol
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch.AbstractDispatchAnalyzer
import lol.fairplay.ghidraapple.analysis.utilities.addCollection
import lol.fairplay.ghidraapple.analysis.utilities.getConstantFromVarNode
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import kotlin.jvm.optionals.getOrNull

class OCTypeInjectorAnalyzer :
    AbstractDispatchAnalyzer<Address>(
        NAME,
        DESCRIPTION,
        AnalyzerType.INSTRUCTION_ANALYZER,
        ObjectiveCDispatchTagAnalyzer.OBJC_ALLOC,
    ) {
    companion object {
        private const val NAME = "Objective-C Type Injection"
        private const val DESCRIPTION = ""

        // This has to run before the data type propagation (but not earlier), otherwise not all alloc calls are found?
        private val PRIORITY = AnalysisPriority.DATA_TYPE_PROPOGATION.before()
        const val ALLOC_DATA = "AllocData"
    }

    init {
        priority = PRIORITY
        setPrototype()
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program?): Boolean = true

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
                }
            }
        }
    }

    override fun getResultForPCodeCall(
        program: Program,
        pcodeOp: PcodeOp,
    ): Address? {
        val clsVarNode = pcodeOp.getInput(1)
        if (clsVarNode == null) {
            throw IllegalArgumentException("Alloc call without argument")
        }
        val r = getConstantFromVarNode(clsVarNode).getOrNull()
        val classAddr = r?.toDefaultAddressSpace(program)
        return classAddr
    }

    override fun processResults(
        program: Program,
        result: Collection<Pair<Reference, Address?>>,
    ) {
        val propMap =
            program.usrPropertyManager.getLongPropertyMap(ALLOC_DATA) ?: program.usrPropertyManager.createLongPropertyMap(
                ALLOC_DATA,
            )
        propMap.addCollection(result.map { (ref, clsAddr) -> ref.fromAddress to clsAddr?.offset })
//            val function = program.functionManager.getFunctionContaining(ref.fromAddress)
//            val signature = generateFunctionSignatureForType(getDataTypeFromSymbol(program.symbolTable.getPrimarySymbol(clsAddr)))
//            HighFunctionDBUtil.writeOverride(function, ref.fromAddress, signature)
    }

    override fun configureDecompiler(): DecompileConfigurer =
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
        fsig.arguments = arrayOf(ParameterDefinitionImpl("cls", type, null))
        return fsig
    }

    /**
     * Takes a symbol like `_OBJC_CLASS_$_CLCircularRegion` and returns the DataType for that class.
     */
    private fun getDataTypeFromSymbol(symbol: Symbol): DataType {
        val className = symbol.name.removePrefix("_OBJC_CLASS_\$_")
        val type = symbol.program.dataTypeManager.getDataType("/GA_OBJC/$className")
        if (type == null) {
            throw IllegalArgumentException("No type found for class $className")
        }
        return type
    }
}
