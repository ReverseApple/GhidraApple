package lol.fairplay.ghidraapple.actions.markasblock

import docking.ActionContext
import docking.action.MenuData
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.context.ProgramLocationContextAction
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

class MarkAsBlockAction : ProgramLocationContextAction("Mark As Objective-C Block", null) {
    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.PKG_NAME)
    }

    private fun setMenuData(blockType: String) {
        popupMenuData =
            MenuData(arrayOf("Mark as Objective-C $blockType Block"), GhidraApplePluginPackage.PKG_NAME)
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
                        context.program.withTransaction<Exception>("Mark Global Block at 0x${context.address}") {
                            ApplyNSConcreteGlobalBlock(context.address).applyTo(context.program)
                        }
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

        val location = typedContext.location

        when (location) {
            is DecompilerLocation -> {
                location.token.lineParent?.let {
                    // Tokens: [variableName], [space], [equals], [space], ["PTR___NSConcreteStackBlock*"], ...
                    if (it.getToken(4).toString().startsWith("PTR___NSConcreteStackBlock")) return true
                }
            }
        }

        // We first check if this is an instruction and look for the start of the building of a stack block.
        typedContext.program.listing.getInstructionAt(typedContext.address)?.let {
            typedContext.program.symbolTable
                .getSymbols(
                    it.referencesFrom
                        .firstOrNull { it.referenceType == RefType.DATA }
                        ?.toAddress
                        ?: return false,
                ).firstOrNull { it.isPrimary }
                ?.apply { if (name != "__NSConcreteStackBlock") return false }
                ?.also { setMenuData("Stack") }
                ?: return false
            return true
        }
            // If this wasn't an instruction, this should be data, so we look for the start global block.
            ?: run {
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
                    ?.apply { if (name != "__NSConcreteGlobalBlock") return false }
                    ?.also { setMenuData("Global") }
                    ?: return false
                return true
            }
    }
}
