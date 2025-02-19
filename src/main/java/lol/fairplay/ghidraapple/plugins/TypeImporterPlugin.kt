package lol.fairplay.ghidraapple.plugins

import docking.ActionContext
import docking.Tool
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.services.DataTypeManagerService
import ghidra.app.util.cparser.C.CParserUtils
import ghidra.framework.Application
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.data.StandAloneDataTypeManager
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import java.io.File
import java.io.IOException
import kotlin.io.path.Path

private class ImportTypesAction(
    owner: String,
    private val tool: Tool,
    private val getCurrentProgram: () -> Program?,
) : DockingAction("Import Types", owner) {
    companion object {
        const val DATA_TYPE_MANAGER_NAME = "poom_smart_types"

        // TODO: Make these work on a general basis.
        const val POOMSMART_IDATYPES_PATH = "/path/to/IDAObjcTypes/"
        const val MACOS_SDK_PATH = "/path/to/MacOSX.sdk/"
    }

    init {
        menuBarData = MenuData(arrayOf("GhidraApple", "Import Types"))
    }

    private fun readParserProfile(file: File): Triple<Array<String>, Array<String>, Array<String>> {
        val filenames = mutableListOf<String>()
        val args = mutableListOf<String>()
        val includePaths = mutableListOf<String>()

        var segmentIndex = 0

        file.forEachLine {
            if (it.isEmpty()) segmentIndex++.also { return@forEachLine }
            when (segmentIndex) {
                0 -> filenames.add(it.trim())
                1 -> args.add(it.trim())
                2 -> includePaths.add(it.trim())
                // There is potentially more data beyond the third segment, but we don't care about it.
                else -> return@forEachLine
            }
        }

        return Triple(filenames.toTypedArray(), includePaths.toTypedArray(), args.toTypedArray())
    }

    override fun actionPerformed(context: ActionContext) {
        val program = getCurrentProgram()
        if (program == null) return
        // TODO: Determine if we actually need this or if we can define these manually.
        val (filenames, includePaths, args) =
            readParserProfile(
                Path(Application.getInstallationDirectory().absolutePath)
                    .resolve("Ghidra")
                    .resolve("Features")
                    .resolve("Base")
                    .resolve("data")
                    .resolve("parserprofiles")
                    .resolve("objc_mac_carbon.prf")
                    .toFile(),
            )
        val currentDataTypeManagers =
            tool
                .getService<DataTypeManagerService>(DataTypeManagerService::class.java)
                .dataTypeManagers
                .also { if (it.any { it.name == DATA_TYPE_MANAGER_NAME }) return }
        val newDataTypeManager = StandAloneDataTypeManager(DATA_TYPE_MANAGER_NAME)
        val results =
            CParserUtils.parseHeaderFiles(
                currentDataTypeManagers,
                // The file names are all Windows-style, so we need to make sure they match the current
                //  platform's path separator type.
                filenames.map { it.replace("\\", File.separator) }.take(1).toTypedArray() +
                    arrayOf(Path(POOMSMART_IDATYPES_PATH).resolve("Ida.h").toString()),
                includePaths +
                    arrayOf(Path(MACOS_SDK_PATH).resolve("usr").resolve("include").toString()),
                // The original args are unhelpful.
                arrayOf(
                    // Otherwise `cdefs.h` will complain
                    "-D__GNUC__=4",
                    // Otherwise `cdefs.h` will complain
                    "-D__arm64__",
                    // Otherwise `TargetConditionals.h` will complain
                    "-DTARGET_CPU_ARM64",
                    // TODO: Add the rest of defines and/or find the ones that something
                    //  like Apple Clang uses.
                ),
                newDataTypeManager,
                TaskMonitor.DUMMY,
            )
        if (!results.successful) {
            throw IOException(results.cppParseMessages)
        }
        TODO("Not yet implemented")
    }
}

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    description = "",
    shortDescription = "",
)
class TypeImporterPlugin(
    tool: PluginTool,
) : ProgramPlugin(tool) {
    init {
        tool.addAction(ImportTypesAction(name, tool, { currentProgram }))
    }
}
