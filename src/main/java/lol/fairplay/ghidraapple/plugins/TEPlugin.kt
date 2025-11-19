package lol.fairplay.ghidraapple.plugins

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.data.FunctionDefinition
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.actions.te.ChooseDataTypeManagerDialog
import lol.fairplay.ghidraapple.actions.te.RetypeFunctionAction
import lol.fairplay.ghidraapple.actions.te.matchingFunctionDefinitionForFunction
import lol.fairplay.ghidraapple.actions.te.retypeFunction
import lol.fairplay.ghidraapple.te.TEParser
import java.io.File

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "TypeExtractor Plugin",
    description = "A plugin to work with TypeExtractor.",
)
class TEPlugin(
    tool: PluginTool,
) : ProgramPlugin(tool) {
    override fun init() {
        tool.addAction(RetypeFunctionAction(name, tool))

        val retypeFuntionsAction =
            object : DockingAction(
                "Re-Type Functions",
                name,
            ) {
                init {
                    menuBarData = MenuData(arrayOf(GhidraApplePluginPackage.PKG_NAME, this.name))
                }

                override fun actionPerformed(context: ActionContext) {
                    tool.showDialog(
                        ChooseDataTypeManagerDialog(
                            tool,
                            currentProgram,
                            null,
                        ) { selectedDataTypeManager, _ ->
                            currentProgram.withTransaction<Exception>("Re-Type Functions") {
                                val dtmFunctionNames =
                                    selectedDataTypeManager
                                        .allDataTypes
                                        .asSequence()
                                        .filter { it is FunctionDefinition }
                                        .map { it.name }
                                        .toList()
                                currentProgram.functionManager
                                    .getFunctions(true)
                                    .filter { dtmFunctionNames.contains(it.name.removePrefix("_")) }
                                    .forEach { function ->
                                        selectedDataTypeManager
                                            .matchingFunctionDefinitionForFunction(function)
                                            ?.let { functionDefinition ->
                                                retypeFunction(
                                                    function,
                                                    functionDefinition,
                                                    currentProgram,
                                                    // We're already inside a transaction.
                                                    useTransaction = false,
                                                )
                                            }
                                    }
                            }
                        },
                    )
                }

                override fun isEnabled(): Boolean = currentProgram != null
            }

        tool.addAction(retypeFuntionsAction)

//        tool.addAction(RetypeFunctionsAction(name, tool))
    }

    fun makeParser(dtmFile: File): TEParser = TEParser(tool, dtmFile)

    fun parseTEOutput(
        teOutputFile: File,
        dtmFile: File,
    ) {
        makeParser(dtmFile).parseEmittedTypes(teOutputFile.readLines())
    }
}
