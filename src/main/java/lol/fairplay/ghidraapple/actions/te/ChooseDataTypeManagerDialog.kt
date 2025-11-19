package lol.fairplay.ghidraapple.actions.te

import docking.DialogComponentProvider
import docking.widgets.table.TableColumnDescriptor
import docking.widgets.table.threaded.ThreadedTableModelStub
import ghidra.app.services.DataTypeManagerService
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.util.datastruct.Accumulator
import ghidra.util.table.GhidraFilterTable
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.addColumn

private fun doesDataTypeMatchFunction(
    dataType: DataType,
    function: Function,
): Boolean = dataType.name == function.name.removePrefix("_") && dataType is FunctionDefinition

class ChooseDataTypeManagerDialog(
    tool: PluginTool,
    private val program: Program,
    private val function: Function?,
    private val callback: (
        selectedDataTypeManager: DataTypeManager,
        matchingFunctionDefinition: FunctionDefinition?,
    ) -> Unit,
) : DialogComponentProvider("Re-Type Function(s): Choose Data Type Manager", true, true, true, false) {
    private var dtmTable: GhidraFilterTable<DataTypeManager> =
        GhidraFilterTable(DataTypeManagersForFunctionTable(tool, function))

    init {
        rootPanel.add(dtmTable)
        addDismissButton()
        addApplyButton()
    }

    override fun applyCallback() {
        callback(
            dtmTable.selectedRowObject,
            dtmTable.selectedRowObject.matchingFunctionDefinitionForFunction(function),
        )
        close()
    }
}

fun DataTypeManager.matchingFunctionDefinitionForFunction(function: Function?): FunctionDefinition? {
    if (function === null) return null
    return this.allDataTypes
        .asSequence()
        .filter { doesDataTypeMatchFunction(it, function) }
        .toList()
        .also {
            if (it.count() != 1) {
//                throw IllegalStateException(
//                    "Data type manager $this has more than one" +
//                        "matching function definition for function ${function.name}!",
//                )
                return null
            }
        }.first() as? FunctionDefinition
}

class DataTypeManagersForFunctionTable(
    private val tool: PluginTool,
    private val function: Function?,
) : ThreadedTableModelStub<DataTypeManager>("", tool) {
    override fun createTableColumnDescriptor(): TableColumnDescriptor<DataTypeManager> {
        val descriptor: TableColumnDescriptor<DataTypeManager> = TableColumnDescriptor<DataTypeManager>()
        descriptor.addColumn("Name", true, String::class.java) { it.name }
        return descriptor
    }

    override fun doLoad(
        accumulator: Accumulator<DataTypeManager>,
        monitor: TaskMonitor,
    ) {
        val dtmService = tool.getService<DataTypeManagerService?>(DataTypeManagerService::class.java)
        if (dtmService == null) return
        with(dtmService) {
            monitor.initialize(dtmService.dataTypeManagers.size.toLong())
            dtmService.dataTypeManagers
                .filter { dtm ->
                    monitor.checkCancelled()
                    if (function == null) true else dtm.matchingFunctionDefinitionForFunction(function) !== null
                }.forEach {
                    monitor.checkCancelled()
                    monitor.incrementProgress(1)
                    accumulator.add(it)
                }
        }
    }
}
