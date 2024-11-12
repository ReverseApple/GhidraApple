package lol.fairplay.ghidraapple.plugins

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing


@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    description = "",
    shortDescription = "",
)
class ClassParserTestingPlugin(tool: PluginTool) : ProgramPlugin(tool) {

    init {
        createActions()
    }

    private fun createActions() {
        val action = object : DockingAction("Analyze Class", name) {
            override fun actionPerformed(context: ActionContext?) {
                if (currentProgram == null) return

                val data = currentProgram.listing.getDefinedDataAt(currentLocation.address) ?: return
                if (data.dataType.name != "class_rw_t") return

                val parser = StructureParsing(currentProgram)
                println(parser.parseClassRw(data.address.unsignedOffset))
            }

        }
        action.menuBarData = MenuData(arrayOf("GhidraApple", "Analyze Class"))
        tool.addAction(action)
    }

}