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
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass


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

    private fun printClassInfo(klass: OCClass) {
        println(klass)
        println("inheritance: ${klass.getInheritance()?.joinToString(", ") { it.name }}")

        println("Resolved methods:")
        klass.resolvedMethods()?.forEach { println("\t${it.name} FROM ${it.parent.name}") }

        println("Resolved properties:")
        klass.resolvedProperties()?.forEach { println("\t${it.name} FROM ${it.parent.name}") }
    }

    private fun createActions() {
        val action = object : DockingAction("Analyze Class", name) {
            override fun actionPerformed(context: ActionContext?) {
                if (currentProgram == null) return

                val data = currentProgram.listing.getDefinedDataAt(currentLocation.address) ?: return
                if (data.dataType.name != "class_t") return

                val parser = StructureParsing(currentProgram)
                val klass = parser.parseClass(data.address.unsignedOffset)
                printClassInfo(klass!!)
            }

        }
        action.menuBarData = MenuData(arrayOf("GhidraApple", "Analyze Class"))
        tool.addAction(action)
    }

}