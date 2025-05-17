package lol.fairplay.ghidraapple.plugins

import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Program
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.actions.choosemsg.ChooseMsgSendCalleeAction
import lol.fairplay.ghidraapple.windows.AllocViewerComponent
import lol.fairplay.ghidraapple.windows.DynamicDispatchComponent

// @formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Objective-C Dynamic Dispatch",
    description = "A plugin to help with Objective-C dynamic dispatches (msgSend family of functions)",
    eventsConsumed = [],
) // @formatter:on
class ObjectiveCDynamicDispatchPlugin(
    plugintool: PluginTool,
) : ProgramPlugin(plugintool) {
    private val allocViewerComponent: AllocViewerComponent
    private val dynamicDispatchTable: DynamicDispatchComponent

    init {
        setupActions()
        dynamicDispatchTable = DynamicDispatchComponent(tool).install(tool)
        allocViewerComponent = AllocViewerComponent(tool).install(tool)
    }

    private fun setupActions() {
        tool.addAction(ChooseMsgSendCalleeAction())
    }

    override fun programActivated(program: Program) {
        super.programActivated(program)
        dynamicDispatchTable.updateProgram(program)
        allocViewerComponent.updateProgram(program)
    }
}
