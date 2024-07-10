package lol.fairplay.ghidraapple.analysis.selectortrampoline

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.MachoLoader
import ghidra.framework.options.OptionType
import ghidra.framework.options.Options
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.mem.MemoryAccessException
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.core.common.MachOCpuID

class SelectorTrampolineAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {

    companion object {
        const val NAME = "Objective-C Selector Trampoline Analysis"
        const val DESCRIPTION = "Identify and rename Objective-C trampoline procedures."
        const val OPT_SHOULD_COPY_REFS = "Copy Trampoline References to Actual Implementations"
        val PRIORITY = AnalysisPriority.DATA_ANALYSIS.before().before()

        const val TRAMPOLINE_TAG = "OBJC_TRAMPOLINE"
        const val TRAMPOLINE_TAG_DESC = "Objective-C Selector Trampoline Function"
    }

    private lateinit var cpuId: MachOCpuID
    private lateinit var opcodeSignature: Array<String>
    private lateinit var program: Program
    private val selectorTrampolines = ArrayList<ObjCTrampoline>()

    private var shouldMoveSelRefs = true

    init {
        setDefaultEnablement(true)
        setPriority(PRIORITY)
    }

    override fun registerOptions(options: Options?, program: Program?) {

        options?.registerOption(
            OPT_SHOULD_COPY_REFS,
            OptionType.BOOLEAN_TYPE,
            shouldMoveSelRefs,
            null,
            "Analyze references to Objective-C trampolines and copy them to the corresponding *actual* method."
        )

    }

    override fun optionsChanged(options: Options?, program: Program?) {
        shouldMoveSelRefs = options?.getBoolean(OPT_SHOULD_COPY_REFS, shouldMoveSelRefs)!!
    }

    private fun functionMatchesOpcodeSignature(function: Function): Boolean {
        val instructions: InstructionIterator = function
            .program
            .listing
            .getInstructions(function.body, true)

        var pos = 0

        while (instructions.hasNext()) {
            val current: Instruction = instructions.next()

            if (current.mnemonicString.equals(opcodeSignature[pos], ignoreCase = true)) {
                pos++
                // if we are at the end of the opcode signature...
                if (pos == opcodeSignature.size) {
                    // return true if we do not have more and false otherwise.
                    return !instructions.hasNext()
                }
            } else {
                break
            }

        }

        return false
    }

    override fun canAnalyze(program: Program): Boolean {
        // todo: consider checking for presence of certain relevant Objective-C sections.

        if (program.executableFormat == MachoLoader.MACH_O_NAME) {
            return try {
                val cpuArch = MachOCpuID.getCPU(program)

                if (cpuArch != null) {
                    cpuId = cpuArch

                    val sig = TrampolineOpcodeSignature.getInstructionSignature(cpuArch)
                    if (sig != null) {
                        opcodeSignature = sig
                    } else {
                        return false
                    }
                } else {
                    return false;
                }

                cpuArch == MachOCpuID.AARCH64 || cpuArch == MachOCpuID.AARCH64E
            } catch (e: MemoryAccessException) {
                false
            }
        }

        return false
    }

    @Throws(CancelledException::class)
    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        this.program = program

        program.functionManager.functionTagManager.createFunctionTag(
            TRAMPOLINE_TAG,
            TRAMPOLINE_TAG_DESC
        )

        val addresses = set.getAddresses(true).toList()

        println("ADDED ${addresses.size} ADDRESSES")

        // Find (and store) functions that match the trampoline instruction signature for the current CPU.
        findTrampolines(monitor, addresses, program)

        renameTrampolines(monitor)

        if (shouldMoveSelRefs) {
            copyXRefData(monitor)
        }

        // todo: eventually separate this from SelectorTrampolineAnalyzer
        monitor.message = "Fixing Objective-C messaging function signatures..."
        fixObjCRuntimeFunctionSig()

        return true
    }

    private fun fixObjCRuntimeFunctionSig() {
        val names = listOf("_objc_retainAutoreleasedReturnValue", "_objc_autorelease")
        val objc_id_datatype = "/_objc2_/ID"

        val datatype = program.dataTypeManager.getDataType(objc_id_datatype)
        val param = ParameterImpl("return_value", datatype, program.getRegister("x0"), program)

        for (funcname in names) {
            val fAddress = program.symbolTable.getSymbols(name).find {
                it.symbolType == SymbolType.FUNCTION
            } ?: continue

            val function = program.functionManager.getFunctionAt(fAddress.address)
            function.updateFunction(
                null,
                null,
                listOf(param),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true,
                SourceType.ANALYSIS
            )
        }

    }

    private fun findTrampolines(
        monitor: TaskMonitor,
        addresses: List<Address>,
        program: Program
    ) {

        monitor.message = "Identifying trampoline functions..."
        monitor.maximum = addresses.size.toLong()

        for (address in addresses) {
            if (monitor.isCancelled) throw CancelledException()

            program.functionManager.getFunctionAt(address)?.let { function ->
                if (functionMatchesOpcodeSignature(function)) {
                    println("Trampoline detected: ${function.name}")
                    selectorTrampolines.add(ObjCTrampoline(function, cpuId))
                    function.addTag(TRAMPOLINE_TAG)
                }
            }

            monitor.progress += 1
        }
    }

    private fun copyXRefData(monitor: TaskMonitor) {
        // On stubs where a SINGLE concrete implementation exists under the same name,
        //  copy the references to the stub, to the identified concrete implementation.

        monitor.message = "Copying stub refs to real implementations..."
        monitor.maximum = selectorTrampolines.size.toLong()
        monitor.progress = 0

        for (trampoline in selectorTrampolines) {

            val actualImplementation = trampoline.findActualImplementation()

            if (actualImplementation == null) {
                monitor.progress += 1
                continue
            }

            val tAddress = trampoline.function.symbol.address

            program.referenceManager.getReferencesTo(tAddress).forEach { reference ->
                // Create call reference from calling function to the actual impl.
                program.referenceManager.addMemoryReference(
                    reference.fromAddress,
                    actualImplementation.address,
                    RefType.UNCONDITIONAL_CALL,
                    SourceType.ANALYSIS,
                    0
                )
            }

            monitor.progress += 1
        }

    }

    private fun renameTrampolines(monitor: TaskMonitor) {
        monitor.message = "Renaming Obj-C Trampolines..."
        monitor.maximum = selectorTrampolines.size.toLong()
        monitor.progress = 0

        for (trampoline in selectorTrampolines) {
            val selector = trampoline.getSelectorString()
            println("${trampoline.function.name} --> $selector")
            trampoline.function.setName(selector, SourceType.ANALYSIS)
            monitor.progress += 1
        }
    }

    override fun analysisEnded(program: Program) {
        super.analysisEnded(program)
        selectorTrampolines.clear()
    }

}
