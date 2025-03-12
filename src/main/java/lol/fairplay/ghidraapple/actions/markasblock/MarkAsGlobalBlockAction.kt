package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ListingActionContext
import ghidra.program.model.data.Pointer
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MarkAsGlobalBlockAction(owner: String) : DockingAction("Mark As Objective-C Global Block", owner) {
    init {
        description = "Mark the current location as an Objective-C Global block"
        popupMenuData = MenuData(arrayOf("Mark as Objective-C Global Block"), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun isValidContext(context: ActionContext): Boolean {
        return context is ListingActionContext
    }

    override fun isEnabledForContext(context: ActionContext): Boolean {
        val typedContext = context as ListingActionContext
        val dataAtLocation =
            typedContext.program.listing.getDataAt(typedContext.address) ?: return false
        if (BlockLayoutDataType.isDataTypeBlockLayoutType(dataAtLocation.dataType)) return false
        if (dataAtLocation.dataType !is Pointer) return false
        typedContext.program.symbolTable
            .getSymbols(
                typedContext.program.address(
                    ByteBuffer.wrap(dataAtLocation.bytes).order(ByteOrder.LITTLE_ENDIAN).long,
                ),
            ).firstOrNull { it.isPrimary }
            ?.apply { if (name != "__NSConcreteGlobalBlock" && name != "__NSGlobalBlock__") return false }
            ?: return false
        return true
    }

    override fun actionPerformed(context: ActionContext) {
        val context = context as ListingActionContext
        context.program.withTransaction<Exception>("Mark Global Block at 0x${context.address}") {
            ApplyNSConcreteGlobalBlock(context.address).applyTo(context.program)
        }
    }
}
