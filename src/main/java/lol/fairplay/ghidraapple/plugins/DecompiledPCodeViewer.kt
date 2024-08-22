package lol.fairplay.ghidraapple.plugins


import docking.ActionContext
import docking.ComponentProvider
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import java.awt.BorderLayout
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea


class DecompiledViewProvider(tool: PluginTool, owner: String, val program: Program) : ComponentProvider(tool, owner, owner) {

    val decompInterface = DecompInterface()
    var address: Address? = null

    lateinit var panel: JPanel

    init {
        decompInterface.openProgram(program)
        buildPanel()
    }

    private fun buildPanel() {
        panel = JPanel(BorderLayout())

        val textArea = JTextArea()
        textArea.isEditable = false

        val taScrollable = JScrollPane(textArea)

        if (address == null) {
            textArea.text = "No function selected."
            panel.add(taScrollable, BorderLayout.CENTER)
            return
        }

        val function = program.functionManager.getFunctionContaining(address)

        if (function == null) {
            textArea.text = "No function selected."
            panel.add(taScrollable, BorderLayout.CENTER)
            return
        }

        val results = decompInterface.decompileFunction(function, 30, null)

        val liftedPCode = StringBuilder()
        results.highFunction.pcodeOps.forEach {
            liftedPCode.append(it.toString() + "\n")
        }

        textArea.text = liftedPCode.toString()

        panel.add(taScrollable, BorderLayout.CENTER)
    }

    override fun getComponent(): JComponent {
        return panel!!
    }

    fun reload() {
        buildPanel()
    }

}


@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    description = "",
    shortDescription = ""
)
class DecompiledPCodeViewerPlugin(tool: PluginTool) : ProgramPlugin(tool) {

    var provider: DecompiledViewProvider? = null

    init {
        createActions()
    }

    private fun createActions() {
        val action = object : DockingAction("View Lifted PCode", name) {
            override fun actionPerformed(context: ActionContext?) {
                if (currentProgram != null) {
                    provider = DecompiledViewProvider(tool, name, currentProgram)
                    provider!!.address = currentLocation.address
                    provider!!.reload()
                    provider!!.setVisible(true)
                }
            }
        }
        action.menuBarData = MenuData(arrayOf("GhidraApple", "View Lifted PCode"))
        tool.addAction(action)
    }

}