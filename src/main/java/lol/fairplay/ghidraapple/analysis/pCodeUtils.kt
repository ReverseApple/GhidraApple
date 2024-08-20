package lol.fairplay.ghidraapple.analysis

import ghidra.program.model.address.Address
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import java.util.*

fun getConstantFromVarNode(varnode: Varnode): Optional<Address> {

    return when {
        varnode.isRegister -> getConstantFromPcodeOp(varnode.def)
        varnode.isConstant -> Optional.of(varnode.address)
        varnode.isAddress -> TODO()
        varnode.isUnique -> getConstantFromPcodeOp(varnode.def)
        else -> TODO()
    }
}

fun getConstantFromPcodeOp(pcodeOp: PcodeOp): Optional<Address> {
    when (pcodeOp.opcode) {
        PcodeOp.CAST -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.COPY -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.PTRSUB -> {
            val ptrSubInput = pcodeOp.inputs.first { !(it.isConstant && it.offset == 0L)}
            return getConstantFromVarNode(ptrSubInput)
        }
        // Multiequal is a phi node, so we can't get _one_ constant from it
        PcodeOp.MULTIEQUAL -> return Optional.empty<Address>()
        else -> TODO("PCode Opcode ${pcodeOp.mnemonic} not yet implemented")

    }

}
