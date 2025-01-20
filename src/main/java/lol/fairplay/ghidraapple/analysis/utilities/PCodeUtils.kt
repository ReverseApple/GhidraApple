package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.Msg
import java.util.Optional

/**
 * Retrieves a constant from a given Varnode, if applicable.
 *
 * @param varnode The Varnode from which to retrieve the constant.
 * @return An Optional containing the constant Address if found, or an empty Optional otherwise.
 */
fun getConstantFromVarNode(varnode: Varnode): Optional<Address> {
    return when {
        varnode.isRegister && varnode.def != null -> getConstantFromPcodeOp(varnode.def)
        varnode.isConstant -> Optional.of(varnode.address)
        varnode.isAddress -> Optional.of(varnode.address)
        varnode.isUnique -> getConstantFromPcodeOp(varnode.def)
        else -> Optional.empty()
    }
}

/**
 * Retrieves a constant address from a given PcodeOp, if applicable.
 *
 * @param pcodeOp The PcodeOp from which to retrieve the constant address.
 * @return An Optional containing the constant Address if found, or an empty Optional otherwise.
 */
fun getConstantFromPcodeOp(pcodeOp: PcodeOp): Optional<Address> {
    when (pcodeOp.opcode) {
        PcodeOp.CAST -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.COPY -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.PTRSUB -> {
            val ptrSubInput = pcodeOp.inputs.first { !(it.isConstant && it.offset == 0L) }
            return getConstantFromVarNode(ptrSubInput)
        }
        PcodeOp.LOAD -> return Optional.empty()
        // Multiequal is a phi node, so we can't get _one_ constant from it
        PcodeOp.MULTIEQUAL -> return Optional.empty<Address>()
        PcodeOp.INDIRECT -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.CALL -> return Optional.empty()
        else -> {
            Msg.error(
                "getConstantFromPcodeOp",
                "Unknown opcode ${pcodeOp.mnemonic} encountered at ${pcodeOp.seqnum.target}",
            )
            return Optional.empty()
        }
    }
}

/**
 * Helper method to convert any kind of address into the same address in the default
 * address space
 * This is useful because constants in the decompiler will be represented as 'addresses'
 * in the 'const' address space, and they need to be converted to the default address space
 * before they can be used in the program API
 */
fun Address.toDefaultAddressSpace(program: Program): Address {
    return program.addressFactory.defaultAddressSpace.getAddress(this.offset)
}

fun getFunctionForPCodeCall(
    program: Program,
    pcodeOp: PcodeOp?,
): Optional<Function> {
    if (pcodeOp != null && pcodeOp.opcode == PcodeOp.CALL) {
        val target = pcodeOp.inputs.getOrNull(0) ?: return Optional.empty()
        if (target.isAddress) {
            return Optional.of(program.functionManager.getFunctionAt(target.address))
        }
    }
    return Optional.empty()
}
