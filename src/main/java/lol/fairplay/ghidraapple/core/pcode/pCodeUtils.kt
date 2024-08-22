package lol.fairplay.ghidraapple.core.pcode

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.ReferenceManager
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.*
import ghidra.util.Msg
import java.util.*

fun getConstantFromVarNode(varnode: Varnode): Optional<Address> {

    return when {
        varnode.isRegister && varnode.def != null -> getConstantFromPcodeOp(varnode.def)
        varnode.isConstant -> Optional.of(varnode.address)
        varnode.isAddress -> Optional.of(varnode.address)
        varnode.isUnique -> getConstantFromPcodeOp(varnode.def)
        else -> Optional.empty()
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
        PcodeOp.LOAD -> return Optional.empty()
        // Multiequal is a phi node, so we can't get _one_ constant from it
        PcodeOp.MULTIEQUAL -> return Optional.empty<Address>()
        PcodeOp.INDIRECT -> return getConstantFromVarNode(pcodeOp.inputs[0])
        else -> {
            Msg.error("getConstantFromPcodeOp",
                "Unknown opcode ${pcodeOp.mnemonic} encountered at ${pcodeOp.seqnum.target}")
            return Optional.empty()
        }


    }

}
