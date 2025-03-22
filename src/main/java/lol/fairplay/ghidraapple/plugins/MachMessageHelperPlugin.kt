package lol.fairplay.ghidraapple.plugins

import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.actions.mach.mig.MarkAsMIGSubsystemAction

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Mach Message Helper Plugin",
    description = "A plugin to help with Mach messages.",
)
class MachMessageHelperPlugin(
    tool: PluginTool,
) : ProgramPlugin(tool) {
    override fun init() {
        tool.addAction(MarkAsMIGSubsystemAction(name, tool))
    }
}
