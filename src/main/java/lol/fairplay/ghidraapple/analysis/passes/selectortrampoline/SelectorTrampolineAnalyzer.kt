package lol.fairplay.ghidraapple.analysis.passes.selectortrampoline

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.decompiler.DecompileResults
import ghidra.app.decompiler.parallel.DecompileConfigurer
import ghidra.app.decompiler.parallel.DecompilerCallback
import ghidra.app.decompiler.parallel.ParallelDecompiler
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.listing.Variable
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.getConstantFromVarNode
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import kotlin.Boolean
import kotlin.Exception
import kotlin.Pair
import kotlin.String
import kotlin.Throws
import kotlin.apply
import kotlin.jvm.optionals.getOrNull
import kotlin.to

class SelectorTrampolineAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {
    companion object {
        const val NAME = "Objective-C Selector Trampoline Analysis"
        const val DESCRIPTION = "Identify and rename Objective-C trampoline procedures."
        const val OPT_SHOULD_COPY_REFS = "Copy Trampoline References to Actual Implementations"
        val PRIORITY = AnalysisPriority.DATA_ANALYSIS.before().before()

        const val TRAMPOLINE_TAG = "OBJC_TRAMPOLINE"
        const val TRAMPOLINE_TAG_DESC = "Objective-C Selector Trampoline Function"

        const val STUB_NAMESPACE_NAME = "stub"
    }

    init {
        setDefaultEnablement(true)
        setPriority(PRIORITY)
        setSupportsOneTimeAnalysis()
    }

    @Throws(CancelledException::class)
    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        // Get all trampoline functions in the addressSet
        program.functionManager.functionTagManager.createFunctionTag(
            TRAMPOLINE_TAG,
            TRAMPOLINE_TAG_DESC,
        )

        val trampolineFunctions =
            program.functionManager
                .getFunctions(set, true)
                .filter { isPlausibleTrampoline(it) }
                .toList()

        monitor.maximum = trampolineFunctions.size.toLong()

        val stubNamespace =
            program.symbolTable.getOrCreateNameSpace(
                program.globalNamespace,
                STUB_NAMESPACE_NAME,
                SourceType.ANALYSIS,
            )

        trampolineFunctions.forEach {
            it.addTag(TRAMPOLINE_TAG)
            it.symbol.setNamespace(stubNamespace)
        }
        findAllSelectors(program, trampolineFunctions, monitor, log).forEach { (func, selector) ->
            applySelectorToFunction(func, selector)
        }
        return true
    }

    /**
     * Core of the trampoline analysis
     */
    private fun findAllSelectors(
        program: Program,
        trampolineFunctions: List<Function>,
        monitor: TaskMonitor,
        log: MessageLog,
    ): List<Pair<Function, String?>> {
//        trampolineFunctions.filter { it.symbol.source  }

        val configurer =
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

        val callback: DecompilerCallback<Pair<Function, String?>> =
            object : DecompilerCallback<Pair<Function, String?>>(program, configurer) {
                @Throws(Exception::class)
                override fun process(
                    results: DecompileResults,
                    m: TaskMonitor,
                ): Pair<Function, String?> {
//                inspectFunction(program, results, monitor)
                    m.increment()

                    if (results.highFunction == null) {
                        println("function name: ${results.function.name}")
                        return results.function to null
                    }

                    val callOp =
                        results.highFunction.pcodeOps
                            .iterator()
                            .asSequence()
                            .singleOrNull { it.opcode == PcodeOp.CALLIND || it.opcode == PcodeOp.CALL }
                    if (callOp != null) {
                        val selAddress = getConstantFromVarNode(callOp.inputs[2]).getOrNull()?.toDefaultAddressSpace(program)
                        if (selAddress != null) {
                            val sel = program.listing.getDataAt(selAddress).value as? String
                            if (sel != null) {
                                return results.function to sel
                            }
                        }
                    } else {
                        log.appendMsg(
                            this@SelectorTrampolineAnalyzer.name,
                            "Could not determine CallOp for function ${results.function.name}",
                        )
                    }
                    return results.function to null
                }
            }

        val results = ParallelDecompiler.decompileFunctions(callback, trampolineFunctions, monitor)
        callback.dispose()
        return results
    }

    private fun applySelectorToFunction(
        func: Function,
        selector: String?,
    ) {
        if (selector != null) {
            if (func.name != selector) {
                // Change the function name based on the selector
                // If it already had a name because symbol information was available, we don't want to overwrite it
                // The name would be the same, but this way the SourceType.IMPORTED is preserved
                func.setName(selector, SourceType.ANALYSIS)
            }
        }

        // Fixup signature of the function
        fixTrampolineSignature(func, selector)
    }

    private fun fixTrampolineSignature(
        func: Function,
        selector: String?,
    ) {
        // Get ID datatype
        val program = func.program
        val idDataType = program.dataTypeManager.getDataType("/_objc2_/ID")
        val returnVariable = ReturnParameterImpl(idDataType, program)

        val arguments = mutableListOf<Variable>(ParameterImpl("recv", idDataType, program))
        if (selector?.contains(':') == true) {
            // We need to add a parameter for the selector otherwise Ghidra doesn't find the varargs in x2 and later
            // But we don't want the add clutter with a useless selector argument for selectors without arguments
            arguments.add(
                ParameterImpl("sel", program.dataTypeManager.getDataType("/_objc2_/SEL"), program),
            )
        }

        func.updateFunction(
            CompilerSpec.CALLING_CONVENTION_unknown,
            returnVariable,
            arguments,
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            false,
            SourceType.ANALYSIS,
        )
        // It's technically not varArgs, because that trampoline will always take the same number of arguments
        // The correct way would be to tell Ghidra to not assume that this is the full signature, and then do
        // regular parameter ID on the function
        func.setVarArgs(true)
    }

    /**
     * Decide if a method is a trampoline method
     * The current minimal version only checks if it's in the "__objc_stubs" segment, but this could in theory
     * be renamed to foil exactly this heuristic
     *
     * If this actually becomes a relevant enough problem to fix, it can be changed to some better heuristic
     */
    private fun isPlausibleTrampoline(function: Function): Boolean {
        // Look up the block that the function is in
        val block = getStubsSegment(function.program)!!
        return block.contains(function.entryPoint)
    }

    override fun canAnalyze(program: Program): Boolean {
        // Check if we have a "__objc_stubs" block
        return getStubsSegment(program) != null
    }

    private fun getStubsSegment(program: Program): MemoryBlock? = program.memory.getBlock("__objc_stubs")
}
