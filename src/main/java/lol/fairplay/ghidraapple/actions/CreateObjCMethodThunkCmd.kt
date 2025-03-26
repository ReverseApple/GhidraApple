package lol.fairplay.ghidraapple.actions

import ghidra.framework.cmd.BackgroundCommand
import ghidra.framework.cmd.Command
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Library
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock.EXTERNAL_BLOCK_NAME
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.db.ObjectiveCClass
import lol.fairplay.ghidraapple.db.Selector

class CreateObjCMethodThunkCmd(
    val cls: ObjectiveCClass,
    val methodName: Selector,
    val sourceType: SourceType = SourceType.USER_DEFINED
): BackgroundCommand<Program>() {
    override fun applyTo(program: Program, monitor: TaskMonitor): Boolean {
        // Find the next free bytes in the external block
//        val extBlock = program.memory.getBlock(EXTERNAL_BLOCK_NAME)
        val address = getNextAddressInExtSpace(program)
        if (cls.namespace?.parentNamespace !is Library) {
            TODO()
        }
        val label = "+[${cls.name}_${methodName}]"
        val extLoc = program.externalManager.addExtFunction(cls.namespace, label, null, sourceType  )
//        val thunkedFunction = program.functionManager.externalFunctions
//            .filter { it.name == methodName && it.parentNamespace == cls.namespace}.single()
        val thunkedFunction = extLoc.function

        // Create a thunk function with the name of the selector
        program.functionManager.createThunkFunction(
            methodName, program.globalNamespace, address, AddressSet(address), thunkedFunction, sourceType
        )

        // Add it to the namespace of the class

        // Find the binary that this class comes from
        // Search it for the method name
        // link the thunk to the external function
        return true
    }

    private fun getNextAddressInExtSpace(program: Program): Address {
        return program.addressFactory.getAddress("ram:000140e8")
    }

    override fun getStatusMsg(): String {
        TODO("Not yet implemented")
    }

    override fun getName(): String {
        return "Create Objective-C Method Thunk"
    }
}
