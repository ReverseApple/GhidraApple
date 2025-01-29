package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ListingActionContext
import ghidra.program.model.data.Pointer
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.isBlockLayoutType
import lol.fairplay.ghidraapple.analysis.utilities.address
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MarkAsGlobalBlockAction(
    owner: String,
) : DockingAction("Mark As Objective-C Global Block", owner) {
    init {
        description = "Mark the current location as an Objective-C Global block"
        popupMenuData = MenuData(arrayOf("Mark as Objective-C Global Block"), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun isValidContext(context: ActionContext): Boolean = context is ListingActionContext

    override fun isEnabledForContext(context: ActionContext): Boolean {
        val typedContext = context as ListingActionContext
        val dataAtLocation =
            typedContext.program.listing.getDataAt(typedContext.address) ?: return false

        // If this is already a block layout, don't allow it to be marked again.
        if (dataAtLocation.dataType.isBlockLayoutType) return false

        // Global blocks start with a pointer. If this isn't a pointer, it's not a global block.
        if (dataAtLocation.dataType !is Pointer) return false

        // If the pointer isn't to the global block symbol, it's not a global block.
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
            MarkNSConcreteGlobalBlock(context.address).applyTo(context.program)
        }
    }
}
