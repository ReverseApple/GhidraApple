package lol.fairplay.ghidraapple.plugins

import docking.action.MenuData
import ghidra.app.decompiler.ClangVariableToken
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.GhidraTypeBuilder.Companion.OBJC_CLASS_CATEGORY
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.ApplyAllocTypeOverrideCommand

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.DIAGNOSTIC,
    description =
        "Includes UI actions for commands and changes that are apply by analyzers, " +
            "but might be useful for interactive testing and debugging",
    shortDescription = "Helper UI Actions for features that should be handled by analyzers ",
)
class DeveloperActionsPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    init {
        createActions()
    }

    private fun createActions() {
        tool.addAction(
            object : AbstractDecompilerAction("Set Inferred Type Override for Call") {
                init {
                    popupMenuData = MenuData(arrayOf("Developer", this.name))
                }

                override fun isEnabledForDecompilerContext(context: DecompilerActionContext): Boolean {
                    return context.tokenAtCursor is ClangVariableToken && context.tokenAtCursor.text.contains("OBJC_CLASS_\$")
                }

                override fun decompilerActionPerformed(context: DecompilerActionContext) {
                    val token = context.tokenAtCursor as ClangVariableToken
                    val className = token.text.removePrefix("PTR_").removePrefix("_OBJC_CLASS_\$_").split("_").first()
                    val structType = context.program.dataTypeManager.getDataType(OBJC_CLASS_CATEGORY, className)
                    val classType = context.program.dataTypeManager.getPointer(structType)
                    context.program.withTransaction<Exception>(
                        "Apply inferred type override ${classType.name} at ${context.location.address}",
                    ) {
                        ApplyAllocTypeOverrideCommand(context.location.address, classType).applyTo(context.program)
                    }
                }
            },
        )
    }
}
