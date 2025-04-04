package lol.fairplay.ghidraapple.plugins

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.services.GraphDisplayBroker
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Data
import ghidra.util.Msg
import ghidra.util.task.TaskLauncher
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.graph.ClassAbstractionGraphTask

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    description = "",
    shortDescription = "",
)
class ObjCInheritanceGraphPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    init {
        createActions()
    }

    private fun createActions() {
        val action =
            object : DockingAction("Graph class abstraction", name) {
                override fun isEnabled(): Boolean {
                    if (currentProgram != null && currentLocation != null) {
                        val data: Data? = currentProgram.listing.getDefinedDataAt(currentLocation.address)
                        return data?.dataType?.name == "class_t"
                    }
                    return false
                }

                override fun actionPerformed(context: ActionContext?) {
                    if (currentProgram == null) return

                    val data = currentProgram.listing.getDefinedDataAt(currentLocation.address) ?: return
                    if (data.dataType.name != "class_t") return

                    val parser = StructureParsing(currentProgram)
                    val classModel = parser.parseClass(data.address.unsignedOffset)!!
                    Msg.debug(this, classModel)

                    // Construct a graph of the abstraction.
                    val graphDisplayBroker = tool.getService(GraphDisplayBroker::class.java)
                    val task = ClassAbstractionGraphTask(tool, graphDisplayBroker, classModel)
                    TaskLauncher(task, tool.toolFrame)
                }
            }
        val sanitizedPath = sanitizeMenuPath(arrayOf("GhidraApple", "Graph class abstraction"))
        action.menuBarData = MenuData(sanitizedPath)
        tool.addAction(action)
    }

    private fun sanitizeMenuPath(path: Array<String>): Array<String> {
        return path.map { it.replace(Regex("\\s{2,}"), " ").trim() }.toTypedArray()
    }
}
