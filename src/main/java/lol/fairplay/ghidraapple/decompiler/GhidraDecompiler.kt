package lol.fairplay.ghidraapple.decompiler

import docking.action.DockingAction
import ghidra.app.plugin.core.decompile.DecompilePlugin
import ghidra.app.plugin.core.decompile.DecompilerProvider
import ghidra.framework.plugintool.PluginTool

class GhidraDecompiler(tool: PluginTool) {

    private val decompilePlugin: DecompilePlugin? = getDecompilePlugin(tool)
    private val decompilerProvider: DecompilerProvider? = decompilePlugin?.let { getDecompilerProvider(it) }

    companion object {
        fun getDecompilePlugin(tool: PluginTool): DecompilePlugin? {
            val managedPlugins = tool.managedPlugins
            return managedPlugins.find { it is DecompilePlugin } as? DecompilePlugin
        }
    }

    fun installAction(action: DockingAction) {
        decompilerProvider?.addLocalAction(action)
    }

}