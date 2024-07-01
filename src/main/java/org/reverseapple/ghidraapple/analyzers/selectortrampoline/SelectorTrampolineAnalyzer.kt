package org.reverseapple.ghidraapple.analyzers.selectortrampoline

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.MachoLoader
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressIterator
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.InstructionIterator
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import org.reverseapple.ghidraapple.utils.MachOCpuID

class SelectorTrampolineAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {

    companion object {
        const val NAME = "Objective-C Selector Trampoline Analyzer"
        const val DESCRIPTION = "Test"
    }

    private lateinit var cpuId: MachOCpuID
    private lateinit var opcodeSignature: Array<String>
    private val selectorTrampolines = ArrayList<ObjCTrampoline>()

    init {
        setDefaultEnablement(true)
        setPriority(AnalysisPriority.DATA_ANALYSIS.before().before());
        setSupportsOneTimeAnalysis()
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
//        val addresses = set.addressRanges.map{ range-> range.maxAddress }
        val addresses = set.getAddresses(true).toList()


        println("ADDED ${addresses.size} ADDRESSES")

        // Find (and store) functions that match the trampoline instruction signature for the current CPU.

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

        // Step 1: rename trampolines.
        renameTrampolines(monitor)

        // Step 2: analyze class implementors.
//        analyzeTrampolineClassImplementors(monitor)

        return true
    }

    fun analyzeTrampolineClassImplementors(monitor: TaskMonitor) {
        monitor.message = "Recovering implementors..."
        monitor.maximum = selectorTrampolines.size.toLong()
        monitor.progress = 0
        TODO()
    }

    fun renameTrampolines(monitor: TaskMonitor) {
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
