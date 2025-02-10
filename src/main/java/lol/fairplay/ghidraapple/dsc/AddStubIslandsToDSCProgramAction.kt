package lol.fairplay.ghidraapple.dsc

import docking.action.MenuData
import ghidra.app.cmd.function.CreateThunkFunctionCmd
import ghidra.app.context.ProgramActionContext
import ghidra.app.context.ProgramContextAction
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Program
import ghidra.util.task.Task
import ghidra.util.task.TaskLauncher
import ghidra.util.task.TaskMonitor
import java.io.File

class AddStubIslandsToDSCProgramAction : ProgramContextAction("Add Stub Islands to DSC Program", "DSC") {
    init {
        menuBarData = MenuData(arrayOf("DSC", "Add Stub Islands to DSC Program"))
    }

    override fun actionPerformed(context: ProgramActionContext) {
        TaskLauncher.launch(
            AddStubIslandsToDSCProgramTask(
                context.program,
                File("/home/fmagin/data/21G93__iPhone16,2/stubs.txt"),
            ),
        )
    }
}

class AddStubIslandsToDSCProgramTask(
    val program: Program,
    val file: File,
) : Task("Add Stub Islands to DSC Program", true, true, true) {
    override fun run(monitor: TaskMonitor) {
        val lines = file.readLines()

        val stubSymbolMap =
            lines
                .asMonitoredSequence(monitor, "Processing ${file.name}")
                .map { it.split(":") }
                .map { Pair(it[0], it[1].trim()) }
                .map { (addressString, nameString) ->
                    program.addressFactory.defaultAddressSpace.getAddress(addressString) to
                        program.symbolTable.getExternalSymbol(
                            nameString,
                        )
                }.map { (address, symbol) -> address to symbol }
                .filter { (address, symbol) -> symbol != null }
                .toMap()
        assert(program.addressFactory.defaultAddressSpace.getAddress(0x213475ed0) in stubSymbolMap)
        monitor.message = "Sorting stubs and existing ranges"
        val existingRanges = program.memory.blocks.map { "EXISTING" to it.addressRange }
        val stubsAndExistingRanges =
            (
                existingRanges +
                    stubSymbolMap.keys.map {
                        "STUB" to AddressRangeImpl(it, 16)
                    }
            ).sortedBy { it.second.minAddress }

        val mergesStubsAndExisting =
            stubsAndExistingRanges
                .asMonitoredSequence(monitor, "Merging stubs and existing ranges")
                .fold(mutableListOf<Pair<String, AddressRange>>()) { acc, (kind, range) ->
                    monitor.checkCancelled()
                    monitor.incrementProgress()
                    if (acc.isEmpty()) {
                        acc.add(kind to range)
                    } else {
                        val (lastKind, lastRange) = acc.last()
                        if (lastKind == kind) {
                            acc[acc.size - 1] = lastKind to AddressRangeImpl(lastRange.minAddress, range.maxAddress)
                        } else {
                            acc.add(kind to range)
                        }
                    }
                    acc
                }.onEach { (kind, range) ->
                    println("$kind: $range")
                }

        program
            .withTransaction<Exception>("Creating Placeholder DSC Mappings") {
                mergesStubsAndExisting
                    .asMonitoredSequence(monitor, "Adding stub blocks to program")
                    .filter { it.first == "STUB" }
                    .forEachIndexed { idx, (kind, range) ->
                        program.memory.createUninitializedBlock(
                            "The vast unknowns ($idx)",
                            range.minAddress,
                            range.length,
                            false,
                        )
                    }
//                val addr = program.addressFactory.defaultAddressSpace.getAddress(0x213476320)
//                val symbol = stubSymbolMap[addr]
//                CreateThunkFunctionCmd(addr, AddressSet(addr, addr.add(16)), symbol).applyTo(program)
                stubSymbolMap.entries
                    .asMonitoredSequence(monitor, "Creating thunks for stubs")
//                    .filter { (address, _) -> address.offset == 0x213476320 }
                    .onEach {
                        println(it)
                    }.map { (address, symbol) ->
                        CreateThunkFunctionCmd(
                            address,
                            AddressSet(address, address.add(16)),
                            symbol,
                        )
                    }.map {
                        it.thunkFunction to it.applyTo(program, monitor)
                    }.filterNot { (_, success) -> success }
                    .forEach { (thunkFunction, _) ->
                        println("Failed for thunk function: $thunkFunction")
                    }
            }
    }
}

fun <T> kotlin.collections.Collection<T>.asMonitoredSequence(
    monitor: TaskMonitor,
    message: String,
): kotlin.sequences.Sequence<T> {
    monitor.progress = 0
    monitor.message = message
    monitor.maximum = this.size.toLong()
    return asSequence().onEachIndexed { index, _ ->
        monitor.checkCancelled()
        monitor.progress = index.toLong()
    }
}
