package lol.fairplay.ghidraapple.analysis.langannotation

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.util.task.Task
import ghidra.util.task.TaskLauncher
import ghidra.util.task.TaskMonitor

import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.langannotation.objc.ObjCFunctionAnnotator


@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    description = "",
    shortDescription = ""
)
class AnnotateFunctionPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    init{
        createActions()
    }

    private fun createActions() {
        val action = object : DockingAction("Annotate Function", name) {
            override fun actionPerformed(context: ActionContext?) {
                if (currentProgram != null) {
                    val function = currentProgram.functionManager.getFunctionAt(currentLocation.address) ?: return
                    val task = object : Task("ObjC Annotation", false, true, false) {
                        override fun run(monitor: TaskMonitor?) {
                            val functionAnnotator = ObjCFunctionAnnotator(function, taskMonitor)
                            functionAnnotator.run()
                        }
                    }

                    TaskLauncher(task)
                }
            }
        }

        action.menuBarData = MenuData(arrayOf("GhidraApple", "Annotate Function"))
        tool?.addAction(action)
    }
}
