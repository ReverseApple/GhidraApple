package org.reverseapple.ghidraapple.analyzers.selectortrampoline

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.MachoLoader
import ghidra.framework.options.OptionType
import ghidra.framework.options.Options
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.InstructionIterator
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import org.reverseapple.ghidraapple.utils.MachOCpuID

class SelectorTrampolineAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {

    companion object {
        const val NAME = "Analyze Objective-C Selector Trampolines"
        const val DESCRIPTION = "Identify and rename Objective-C trampoline procedures."

        const val OPT_SHOULD_COPY_REFS = "Copy Trampoline References to Actual Implementations"
    }

    private lateinit var cpuId: MachOCpuID
    private lateinit var opcodeSignature: Array<String>
    private lateinit var program: Program
    private val selectorTrampolines = ArrayList<ObjCTrampoline>()

    private var shouldMoveSelRefs = true

    init {
        setDefaultEnablement(true)
        setPriority(AnalysisPriority.DATA_ANALYSIS.before().before())
    }

    override fun registerOptions(options: Options?, program: Program?) {

        options?.registerOption(
            OPT_SHOULD_COPY_REFS,
            OptionType.BOOLEAN_TYPE,
            shouldMoveSelRefs,
            null,
            null
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
                    opcodeSignature = TrampolineOpcodeSignature.getInstructionSignature(cpuArch)
                    cpuId = cpuArch
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
        val addresses = set.getAddresses(true).toList()


        println("ADDED ${addresses.size} ADDRESSES")

        // Find (and store) functions that match the trampoline instruction signature for the current CPU.
        findTrampolines(monitor, addresses, program)

        // Step 1: rename trampolines.
        renameTrampolines(monitor)

        // Step 2: analyze class implementors.
        //  analyzeTrampolineClassImplementors(monitor)
        if (shouldMoveSelRefs) {
            copyXRefData(monitor)
        }

        return true
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
                }
            }

            monitor.progress += 1
        }
    }

    fun analyzeTrampolineClassImplementors(monitor: TaskMonitor) {
        monitor.message = "Recovering implementors..."
        monitor.maximum = selectorTrampolines.size.toLong()
        monitor.progress = 0
        TODO()
    }

    private fun copyXRefData(monitor: TaskMonitor) {
        // On stubs where a SINGLE concrete implementation exists under the same name,
        //  copy the references to the stub, to the identified concrete implementation.

        monitor.message = "Copying stub refs to real implementations..."
        monitor.maximum = selectorTrampolines.size.toLong()
        monitor.progress = 0

        for (trampoline in selectorTrampolines) {
            val selName = trampoline.getSelectorString()

            if (selName == null) {
                println("WARNING: ${trampoline.function.body.minAddress} has null selector.")
                // need to jump here.
                monitor.progress += 1
                continue
            }

            val symbols = program.symbolTable.getSymbols(selName).filter { symbol->
                symbol.symbolType == SymbolType.FUNCTION && trampoline.function.symbol != symbol
            }

            if (symbols.size == 1) {
                val addr = trampoline.function.body.minAddress
                program.referenceManager.getReferencesTo(addr).forEach { reference ->
                    // Create call reference from calling function to the actual impl.
                    program.referenceManager.addMemoryReference(
                        reference.fromAddress,
                        symbols[0].address,
                        RefType.UNCONDITIONAL_CALL,
                        SourceType.ANALYSIS,
                        0
                    )
                }
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
