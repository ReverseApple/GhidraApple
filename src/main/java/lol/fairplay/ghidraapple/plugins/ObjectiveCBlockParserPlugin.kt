package lol.fairplay.ghidraapple.plugins

import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.actions.markasblock.MarkAsGlobalBlockAction
import lol.fairplay.ghidraapple.actions.markasblock.MarkAsStackBlockAction

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Objective-C Block Parser",
    description = "A plugin to help with Objective-C blocks",
)
class ObjectiveCBlockParserPlugin(
    tool: PluginTool,
) : ProgramPlugin(tool) {
    override fun init() {
        tool.addAction(MarkAsGlobalBlockAction(name))
        tool.addAction(MarkAsStackBlockAction(name, tool))
    }
}
