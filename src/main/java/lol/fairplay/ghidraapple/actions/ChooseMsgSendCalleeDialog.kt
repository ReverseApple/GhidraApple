package lol.fairplay.ghidraapple.actions

import docking.DialogComponentProvider
import docking.Tool
import docking.widgets.table.AbstractDynamicTableColumn
import docking.widgets.table.TableColumnDescriptor
import docking.widgets.table.threaded.ThreadedTableModelStub
import ghidra.docking.settings.Settings
import ghidra.framework.plugintool.ServiceProvider
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection
import ghidra.util.datastruct.Accumulator
import ghidra.util.table.GhidraFilterTable
import ghidra.util.table.ProgramTableModel
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.setCallTarget


class ChooseMsgSendCalleeDialog(private val tool: Tool,
                                private val program: Program,
                                private val callsite: Address,
                                private val selector: String? // TODO: Later we can add a selector to filter the functions
): DialogComponentProvider("Choose msgSend Callee", true, true, true, false) {
    private var functionsTable: GhidraFilterTable<Function>

    init {

        val matchingFunctionsTable = FunctionsForSelectorTable(tool, program.functionManager, selector)
        functionsTable = GhidraFilterTable<Function>(matchingFunctionsTable)

        rootPanel.add(functionsTable)

        // Add select button with action
        addDismissButton()
        addApplyButton()

    }

    override fun applyCallback() {

        functionsTable.selectedRowObject?.let { function ->
            println("Selected function: ${function.name}")
            program.withTransaction<Exception>("ChooseMsgSendCalleeDialog") {
                program.referenceManager.setCallTarget(callsite, function, SourceType.USER_DEFINED)
            }
            close()
        }
    }
}

class FunctionsForSelectorTable(tool: Tool, val functionManager: FunctionManager, val selector: String?): ThreadedTableModelStub<Function>("", tool), ProgramTableModel{
    override fun createTableColumnDescriptor(): TableColumnDescriptor<Function> {
        val descriptor: TableColumnDescriptor<Function> = TableColumnDescriptor<Function>()
        descriptor.addVisibleColumn(object: AbstractDynamicTableColumn<Function, String, Any?>(){
            override fun getColumnName(): String {
                return "Name"
            }

            override fun getValue(
                rowObject: Function,
                settings: Settings,
                data: Any?,
                serviceProvider: ServiceProvider
            ): String {
                return rowObject.name
            }
        })
        descriptor.addVisibleColumn(object: AbstractDynamicTableColumn<Function, String, Any?>(){
            override fun getColumnName(): String {
                return "Class"
            }

            override fun getValue(
                rowObject: Function,
                settings: Settings,
                data: Any?,
                serviceProvider: ServiceProvider
            ): String {
                return rowObject.parentNamespace.name
            }
        })

        return descriptor
    }

    override fun doLoad(accumulator: Accumulator<Function>, monitor: TaskMonitor) {
        with (functionManager){
            monitor.initialize(functionCount.toLong())
            getFunctions(true).filter {
                monitor.checkCancelled()
                selector == null || it.name == selector
            }.forEach {
                monitor.checkCancelled()
                monitor.incrementProgress(1)
                accumulator.add(it)
            }
        }
    }

    override fun getProgramLocation(modelRow: Int, modelColumn: Int): ProgramLocation {
        val func = getRowObject(modelRow)
        return ProgramLocation(func.program, func.entryPoint)
    }

    override fun getProgramSelection(modelRows: IntArray?): ProgramSelection {
        return ProgramSelection();
    }

    override fun getProgram(): Program {
        return functionManager.program
    }

}
