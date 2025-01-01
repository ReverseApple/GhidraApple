package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.function.FunctionDB
import ghidra.program.database.symbol.FunctionSymbol
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.DataType
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.PcodeOpAST
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.getConstantFromVarNode
import kotlin.jvm.optionals.getOrNull


data class AllocInfo(val function: Function, val callsite: Address, val signature: FunctionSignature)

class OCTypeInjectorAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER) {

    lateinit var program: Program

    companion object {
        private const val NAME = "Objective-C Type Injection"
        private const val DESCRIPTION = ""
        // This has to run before the data type propagation (but not earlier), otherwise not all alloc calls are found?
        private val PRIORITY = AnalysisPriority.DATA_TYPE_PROPOGATION.before()
    }

    init {
        priority = PRIORITY
        setPrototype()
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program?): Boolean {
        this.program = program!!
        return allocFnSymbols().isNotEmpty()
    }

    override fun added(program: Program, set: AddressSetView, taskMonitor: TaskMonitor, messageLog: MessageLog): Boolean {
        // Make sure that the alloc calls have the correct type signature setup
        // This has to happen in a separate transaction, otherwise the overrides later will not be applied
        program.withTransaction<Exception>("Setup alloc signatures"){
            allocFnSymbols().forEach {
                val func = it.`object` as FunctionDB
                val id = program.dataTypeManager.getDataType("/_objc2_/ID")
                if (func.signature.arguments.isEmpty()) {
                    func.addParameter(ParameterImpl("cls", id, program), SourceType.IMPORTED)
                    func.setReturnType(id, SourceType.IMPORTED)
                }
            }
        }



        // Get all calls to _objc_alloc in the AddressSet that should be analyzed
        val toAnalyze: Map<Function, List<Address>> = getAllocCallsitesInAddressSet(set)
        if (toAnalyze.isEmpty()) {
            return false
        }
        Msg.info(this, "Analyzing ${toAnalyze.size} functions with ${toAnalyze.values.sumOf { it.size }} alloc calls.")

        val results = analyzeAllocCallsites(program, taskMonitor, messageLog, toAnalyze)

        Msg.info(this, "Successfully analyzed ${results.size} callsites")

        results.forEach { (function, callsite, signature) ->
                HighFunctionDBUtil.writeOverride(function, callsite, signature)
            }
        return true
    }

    private fun analyzeAllocCallsites(program: Program, taskMonitor: TaskMonitor, messageLog: MessageLog, toAnalyze: Map<Function, List<Address>>): List<AllocInfo> {
        val objectLookUp: Map<Long, Symbol> = program.symbolTable.symbolIterator
            .filter { it.name.startsWith("_OBJC_CLASS_\$_") || it.parentNamespace.name == "class_t" }
            .filter { !it.isExternal }
            .associate { it.address.offset to it }

        val decompiler = DecompInterface()
        decompiler.openProgram(program)
        decompiler.setSimplificationStyle("firstpass")
        decompiler.setOptions(
            DecompileOptions().apply { this.isRespectReadOnly = true }
        )

        val result: MutableList<AllocInfo> = mutableListOf()

        taskMonitor.maximum = toAnalyze.size.toLong()

        for ((function, callsites) in toAnalyze) {

            taskMonitor.message = "Analyzing alloc calls in ${function}"

            val decompiled = decompiler.decompileFunction(function, 30, taskMonitor)

            taskMonitor.checkCancelled()

            val highFunction = decompiled.highFunction
            if (highFunction == null) {
                Msg.error(this, "Failed to inject types: highFunction is null for ${function.name}")
                messageLog.appendMsg(NAME, "Failed to inject types: highFunction is null for ${function.name}")
                continue
            }

            Msg.debug(this, "Analyzing ${function.name} @ ${function.entryPoint}...")

            val allocCalls: List<PcodeOpAST> = highFunction.pcodeOps.asSequence()
                .filter { it.opcode == PcodeOp.CALL }
                .filter { it.seqnum.target in callsites && it.inputs.size == 2 }
                .toList()
            if (allocCalls.size != callsites.size){
                messageLog.appendMsg(NAME, "Couldn't find P-Code OP for some objc_alloc calls in ${function}")
            }

            for (allocCall in allocCalls) {
                val allocParameter = allocCall.inputs[1]

                val apSymbol = allocParameter.high.symbol
                if (apSymbol?.isParameter == true) {
                    messageLog.appendMsg(NAME, "Skipping alloc call because ${apSymbol.name} is a function parameter.")
                    continue
                }

                val const = getConstantFromVarNode(allocParameter).getOrNull()
                if (const == null) {
                    val errorMsg = "Could not find constant for ${allocCall.seqnum} in ${function.name}"
                    Msg.error(this, errorMsg)
                    messageLog.appendMsg(NAME, errorMsg)
                    continue
                }
                val allocatedSymbol = objectLookUp[const.offset]
                if (allocatedSymbol != null){
                    runCatching {
                        val ocType = getDataTypeFromSymbol(allocatedSymbol!!)
                        result.add(AllocInfo(function, allocCall.seqnum.target, generateFunctionSignatureForType(ocType)))
                    }.onFailure { error ->
                        Msg.error(this, "Failed to inject type for ${allocatedSymbol.name} in ${function.name}", error)
                    }
                }
                else {
                    messageLog.appendMsg(NAME, "Could not find symbol for constant $const in ${function.name}")
                }

            }
            taskMonitor.incrementProgress()
        }

        decompiler.closeProgram()
        decompiler.dispose()
        return result
    }

    private fun generateFunctionSignatureForType(type: DataType): FunctionSignature {
        val fsig = FunctionDefinitionDataType("tmpname")
        fsig.returnType = type;
        fsig.arguments = arrayOf(ParameterDefinitionImpl("cls", type, null))
        return fsig
    }

    /**
     * Takes a symbol like `_OBJC_CLASS_$_CLCircularRegion` and returns the DataType for that class.
     */
    private fun getDataTypeFromSymbol(symbol: Symbol): DataType {

        val className = symbol.name.removePrefix("_OBJC_CLASS_\$_")
        val type = program.dataTypeManager.getDataType("/GA_OBJC/$className")
        return type
    }


    private fun allocFnSymbols(): List<FunctionSymbol> {
        val result = mutableListOf<FunctionSymbol>()
        val allocNames = listOf(
            "_objc_alloc",
            "_objc_alloc_init",
            "_objc_allocWithZone"
        )
        allocNames.forEach { name ->
            program.symbolTable.getSymbols(name).filterIsInstance<FunctionSymbol>().firstOrNull()?.let { result.add(it) }
        }

        return result
    }

    private fun getAllocCallsitesInAddressSet(set: AddressSetView? = null): Map<Function, List<Address>> {

        // TODO: We should also collect calls to the allocWithZone selector here
        return allocFnSymbols().map { symbol -> program.referenceManager.getReferencesTo(symbol.address)
            .filter { set == null || it.fromAddress in set }
            .filter { it.referenceType.isCall }
            .filter { program.functionManager.getFunctionContaining(it.fromAddress) != null}
            .map { it.fromAddress}
        }
            .flatten()
            // Group all the callsites by the function they are in
            .groupBy {
                address -> program.functionManager.getFunctionContaining(address)
            }
    }

}
