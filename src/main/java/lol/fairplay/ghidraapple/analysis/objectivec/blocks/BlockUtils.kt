package lol.fairplay.ghidraapple.analysis.objectivec.blocks

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.StackReference
import ghidra.program.util.ProgramLocation
import lol.fairplay.ghidraapple.analysis.utilities.getLabelAtAddress

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
