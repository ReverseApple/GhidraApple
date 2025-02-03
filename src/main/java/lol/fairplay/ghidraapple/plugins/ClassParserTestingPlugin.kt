package lol.fairplay.ghidraapple.plugins

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Data
import ghidra.util.Msg
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
        Msg.debug(this, klass)
        Msg.debug(this, "inheritance: ${klass.getInheritance()?.joinToString(", ") { it.name }}")

        Msg.debug(this, "Resolved methods:")
        klass.resolvedMethods().forEach {
            it.abstract().last().let { Msg.debug(this, "\t${it.name} FROM ${it.parent.name}") }
        }

        Msg.debug(this, "Resolved properties:")
        klass.resolvedProperties().forEach {
            val abstract = it.abstract().last()
            Msg.debug(this, "\t${it.name} FROM ${abstract.parent.name} IVAR: ${ abstract.getBackingIvar()?.name ?: "None"}")
        }
    }

    private fun createActions() {
        val action =
            object : DockingAction("Analyze Class", name) {
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
                    val klass = parser.parseClass(data.address.unsignedOffset)
                    printClassInfo(klass!!)
                }
            }
        action.menuBarData = MenuData(arrayOf("GhidraApple", "Analyze Class"))
        tool.addAction(action)
    }
}
