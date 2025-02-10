package lol.fairplay.ghidraapple.plugins

import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.dsc.AddStubIslandsToDSCProgramAction

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Helpers for the Dynamic Shared Cache",
    description = ""
) //@formatter:on
class DSCHelperPlugin(plugintool: PluginTool) : ProgramPlugin(plugintool) {
    init {
        setupActions()
    }

    private fun setupActions() {
        tool.addAction(AddStubIslandsToDSCProgramAction())
    }
}