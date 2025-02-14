package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.context.ProgramLocationContextAction
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.program.model.data.Pointer
import ghidra.program.model.symbol.RefType
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MarkAsBlockAction : ProgramLocationContextAction("Mark As Objective-C Block", null) {
    companion object {
        private fun makeMenuItemText(blockType: String) = "Mark as Objective-C $blockType Block"
    }

    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(context: ProgramLocationActionContext) {
        when (context) {
            is CodeViewerActionContext -> {
                context.program.listing
                    .getInstructionAt(context.address)
                    ?.let {
                        markStackBlock(
                            context.program,
                            context.program.listing
                                .getFunctionContaining(context.address),
                            it,
                        )
                    }
                    ?: run {
                        markGlobalBlock(context.program, context.address)
                    }
            }

            is DecompilerActionContext -> {
                markStackBlock(
                    context.program,
                    context.function,
                    context.program.listing
                        .getInstructionAt(context.address),
                )
            }
        }
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean {
        val typedContext =
            context as? ProgramLocationActionContext ?: return false
        if (BlockLayoutDataType.isLocationBlockLayout(typedContext.location)) return false

        typedContext.program.listing.getInstructionAt(typedContext.address)?.let {
            val pointerAddress =
                it.referencesFrom
                    .firstOrNull { it.referenceType == RefType.DATA }
                    ?.toAddress ?: return false
            typedContext.program.symbolTable
                .getSymbols(pointerAddress)
                .firstOrNull { it.isPrimary }
                ?.apply { if (name != "__NSConcreteStackBlock") return false }
                ?.also {
                    popupMenuData =
                        MenuData(
                            arrayOf(makeMenuItemText("Stack")),
                            GhidraApplePluginPackage.PKG_NAME,
                        )
                }
                ?: return false
            return true
        } ?: run {
            val dataAtLocation =
                typedContext.program.listing.getDataAt(typedContext.address) ?: return false
            if (BlockLayoutDataType.isDataTypeBlockLayoutType(dataAtLocation.dataType)) return false
            if (dataAtLocation.dataType !is Pointer) return false
            val pointerAddress =
                typedContext.program.address(
                    ByteBuffer.wrap(dataAtLocation.bytes).order(ByteOrder.LITTLE_ENDIAN).long,
                )
            typedContext.program.symbolTable
                .getSymbols(pointerAddress)
                .firstOrNull { it.isPrimary }
                ?.apply { if (name != "__NSConcreteGlobalBlock") return false }
                ?.also {
                    popupMenuData =
                        MenuData(
                            arrayOf(makeMenuItemText("Global")),
                            GhidraApplePluginPackage.PKG_NAME,
                        )
                }
                ?: return false
            return true
        }
        return false
    }
}
