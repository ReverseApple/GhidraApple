package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.decompiler.DecompilerLocation
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.program.model.data.Pointer
import ghidra.program.model.symbol.RefType
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.utilities.address
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MarkAsBlockAction : DockingAction("Mark As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    override fun actionPerformed(actionContext: ActionContext?) {
        val typedContext =
            actionContext as? ProgramLocationActionContext ?: return

        when (typedContext) {
            is CodeViewerActionContext ->
                typedContext.program.listing
                    .getInstructionAt(typedContext.address)
                    ?.let {
                        markStackBlock(
                            typedContext.program,
                            typedContext.program.listing.getFunctionContaining(typedContext.address),
                            it,
                        )
                    }
                    ?: run {
                        markGlobalBlock(typedContext.program, typedContext.address)
                    }
            is DecompilerActionContext -> {
                val decompilerLocation =
                    typedContext.location as DecompilerLocation
                val selectedInstruction =
                    typedContext.program.listing.getInstructionAt(typedContext.address)

                markStackBlock(
                    typedContext.program,
                    typedContext.function,
                    selectedInstruction,
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
                ?: return false
            return true
        }
        return false
    }
}
