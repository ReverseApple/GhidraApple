package lol.fairplay.ghidraapple.plugins

import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import lol.fairplay.ghidraapple.GhidraApplePluginPackage


@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.CODE_VIEWER,
    shortDescription = "Objective-C Decompilation",
    description = "Not ready for release."
)
class GADecompilerPlugin(
    tool: PluginTool
) : ProgramPlugin(tool) {

}
