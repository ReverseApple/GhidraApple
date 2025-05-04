package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.formats.gfilesystem.FSRL
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.StackReference
import ghidra.program.util.ProgramLocation
import ghidra.util.task.Task
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.getLabelAtAddress
import lol.fairplay.ghidraapple.analysis.utilities.getPointersToSymbol

fun Program.isAddressBlockLayout(address: Address) =
    listing
        .getDataAt(address)
        ?.dataType
        ?.isBlockLayoutType == true ||
        listing
            .getFunctionContaining(address)
            ?.stackFrame
            ?.stackVariables
            ?.firstOrNull { stackVariable ->
                stackVariable.stackOffset ==
                    listing
                        .getInstructionAt(address)
                        .referencesFrom
                        .filterIsInstance<StackReference>()
                        .firstOrNull()
                        ?.stackOffset
            }?.dataType
            ?.isBlockLayoutType == true

val ProgramLocation.isBlockLayout get() = program.isAddressBlockLayout(address)

val DataType.isBlockLayoutType get() =
    this is BlockLayoutDataType ||
        // We fall back to the name and category path, as most instances won't be of our own class.
        name.startsWith(BlockLayoutDataType().name) &&
        categoryPath.toString() == BLOCK_CATEGORY_PATH_STRING

val Instruction.doesReferenceStackBlockSymbol get() =
    referencesFrom
        .any {
            program.getLabelAtAddress(it.toAddress).let { label ->
                arrayOf(
                    // The instruction references the symbols themselves.
                    "__NSConcreteStackBlock",
                    "__NSStackBlock__",
                    // The instruction references a pointer to the symbols.
                    "PTR___NSConcreteStackBlock_${it.toAddress}",
                    "PTR___NSStackBlock__${it.toAddress}",
                ).contains(label)
            }
        }

fun isAddressStackBlockPointer(
    address: Address,
    program: Program,
): Boolean {
    val data = program.listing.getDataAt(address)
    if (data == null || data.dataType !is Pointer) {
        return false
    }
    val pointee = data.value as? Address ?: return false
    return program.getLabelAtAddress(pointee).let { label ->
        arrayOf(
            "__NSConcreteStackBlock",
            "__NSStackBlock__",
        ).contains(label)
    }
}

fun doesPCodeOpPutStackBlockPointerOnStack(
    op: PcodeOp,
    program: Program,
): Boolean {
    if (op.output?.address?.isStackAddress != true) return false
    return op.inputs.any { isAddressStackBlockPointer(it.address, program) }
}

class FindGlobalBlockSymbolPointers(
    val program: Program,
) : Task("Find Global Block Symbol Pointers") {
    var addresses: Set<Address> = emptySet()

    override fun run(monitor: TaskMonitor) {
        this.addresses =
            FileSystemService
                .getInstance()
                .getByteProvider(FSRL.fromProgram(program), true, monitor)
                // We first get all the sections named "__const".
                .let {
                    MachHeader(it)
                        .parse()
                        .allSections
                        .filter { it.sectionName == "__const" }
                }
                // Then we map those to the block(s) that are named similarly and start at the same address.
                // TODO: Should we just assume this will always be one-to-one and use `map` instead of `flatMap`?
                .flatMap { machSection ->
                    program.memory.blocks
                        .filter { it.name == "__const" && it.start.offset == machSection.address }
                }
                // Finally, we look for pointers to the global block symbol and its alias.
                .flatMap { constMemoryBlock ->
                    program.getPointersToSymbol("__NSConcreteGlobalBlock", constMemoryBlock) +
                        program.getPointersToSymbol("__NSGlobalBlock__", constMemoryBlock)
                }
                // We make this a set to avoid duplicate entries.
                .toSet()
    }
}
