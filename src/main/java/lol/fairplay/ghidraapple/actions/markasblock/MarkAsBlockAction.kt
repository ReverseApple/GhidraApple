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
            // If this is [CodeViewerActionContext], then it came from the disassembly Listing. It could be
            //  either a stack block or a global block.
            is CodeViewerActionContext -> {
                context.program.listing
                    // If there is an instruction at the address, we assume this is a stack block.
                    .getInstructionAt(context.address)
                    ?.let {
                        context.program.withTransaction<Exception>("Mark Stack Block at 0x${context.address}") {
                            ApplyNSConcreteStackBlock(context.program, context.address).applyTo(context.program)
                        }
                    }
                    // If there was no instruction, we assume this is a global block.
                    ?: run {
                        context.program.withTransaction<Exception>("Mark Global Block at 0x${context.address}") {
                            ApplyNSConcreteGlobalBlock(context.address).applyTo(context.program)
                        }
                    }
            }

            // If this is [DecompilerActionContext], it could only have come from the Decompile pane, so we
            //  assume it is a stack block (being built inside the function).
            is DecompilerActionContext -> {
                context.program.withTransaction<Exception>("Mark Global Block at 0x${context.address}") {
                    ApplyNSConcreteStackBlock(context.program, context.address).applyTo(context.program)
                }
            }
        }
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean {
        val typedContext =
            context as? ProgramLocationActionContext ?: return false
        if (BlockLayoutDataType.isLocationBlockLayout(typedContext.location)) return false

        val location = typedContext.location

        // This is a quick-and-dirty check for cases the latter tests wouldn't catch.
        when (location) {
            is DecompilerLocation -> {
                location.token.lineParent?.let {
                    // Tokens: [variableName], [space], [equals], [space], ["PTR___NSConcreteStackBlock*"], ...
                    if (it.getToken(4).toString().startsWith("PTR___NSConcreteStackBlock")) return true
                }
            }
        }

        // We check if this is an instruction and look for the start of the building of a stack block.
        typedContext.program.listing.getInstructionAt(typedContext.address)?.let {
            typedContext.program.symbolTable
                .getSymbols(
                    it.referencesFrom
                        .firstOrNull { it.referenceType == RefType.DATA }
                        ?.toAddress
                        ?: return false,
                ).firstOrNull { it.isPrimary }
                ?.apply { if (name != "__NSConcreteStackBlock" && name != "__NSStackBlock__") return false }
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
                    ?.apply { if (name != "__NSConcreteGlobalBlock" && name != "__NSGlobalBlock__") return false }
                    ?.also { setMenuData("Global") }
                    ?: return false
                return true
            }
    }
}
