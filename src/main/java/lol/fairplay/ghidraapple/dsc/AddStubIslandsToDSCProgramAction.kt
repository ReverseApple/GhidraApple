package lol.fairplay.ghidraapple.dsc

import docking.action.MenuData
import ghidra.app.cmd.function.CreateThunkFunctionCmd
import ghidra.app.context.ProgramActionContext
import ghidra.app.context.ProgramContextAction
import ghidra.formats.gfilesystem.FSRL
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Reference
import ghidra.util.task.Task
import ghidra.util.task.TaskLauncher
import ghidra.util.task.TaskMonitor
import java.io.File

class AddStubIslandsToDSCProgramAction : ProgramContextAction("Add Stub Islands to DSC Program", "DSC") {
    init {
        menuBarData = MenuData(arrayOf("DSC", "Add Stub Islands to DSC Program"))
    }

    override fun actionPerformed(context: ProgramActionContext) {
        val fsrl = FSRL.fromProgram(context.program)
        val cacheFile = File(fsrl.fs.toPrettyFullpathString().removeSuffix("|"))
        TaskLauncher.launch(
            AddStubIslandsToDSCProgramTask(
                context.program,
                File(cacheFile.parentFile, "stubs.txt"),
            ),
        )
    }
}

class AddStubIslandsToDSCProgramTask(
    val program: Program,
    val file: File,
) : Task("Add Stub Islands to DSC Program", true, true, true) {
    val MAX_GAP = 0x4_0000

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
        monitor.message = "Sorting stubs and existing ranges"

        val missingDestinations =
            Companion.getReferencedAddressesOutsideCurrentAddressSpace(program)
                .map { it.key }
                .map { it to stubSymbolMap[it] }
                .filter { it.second != null }
        val missingRanges =
            missingDestinations.fold(mutableListOf<AddressRange>()) {
                    acc, (address, _) ->
                if (acc.isEmpty()) {
                    acc.add(AddressRangeImpl(address, address))
                } else {
                    // Check if the distance to the last range is less than the maximum gap
                    val lastRange = acc.last().maxAddress
                    if (address.subtract(lastRange) < MAX_GAP) {
                        acc[acc.size - 1] = AddressRangeImpl(acc.last().minAddress, address)
                    } else {
                        acc.add(AddressRangeImpl(address, address))
                    }
                }
                acc
            }

        program
            .withTransaction<Exception>("Creating Placeholder DSC Mappings") {
                missingRanges
                    .asMonitoredSequence(monitor, "Adding stub blocks to program")
                    .forEachIndexed { idx, range ->
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
                missingDestinations
                    .asMonitoredSequence(monitor, "Creating thunks for stubs")
//                    .filter { (address, _) -> address.offset == 0x213476320 }
                    .onEach {
                        println(it)
                    }.map { (address, symbol) ->
                        CreateThunkFunctionCmd(
                            address,
                            AddressSet(address, address.add(8)),
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

    companion object {
        public fun getReferencedAddressesOutsideCurrentAddressSpace(program: Program): Map<Address, List<Reference>> {
            val existingRanges = program.memory.blocks.map { it.addressRange }.sortedBy { it.minAddress }

            val intermediateGaps =
                existingRanges.windowed(2).map { (first, second) ->
                    AddressRangeImpl(first.maxAddress, second.minAddress)
                }
            val initialGap =
                AddressRangeImpl(
                    program.addressFactory.defaultAddressSpace.getAddress(0),
                    existingRanges.first().minAddress,
                )
            val finalGap =
                AddressRangeImpl(
                    existingRanges.last().maxAddress,
                    program.addressFactory.defaultAddressSpace.getAddress(
                        program.maxAddress.offset,
                    ),
                )
            val gaps: List<AddressRangeImpl> = listOf(initialGap) + intermediateGaps + listOf(finalGap)

            val gapSet =
                gaps.fold(AddressSet()) { acc, gap ->
                    acc.add(gap)
                    acc
                }

            val outSideDestinations = program.referenceManager.getReferenceDestinationIterator(gapSet, true).toList()
            return outSideDestinations.associateWith { program.referenceManager.getReferencesTo(it).toList() }
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
