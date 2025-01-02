package lol.fairplay.ghidraapple.actions

import docking.DialogComponentProvider
import docking.Tool
import docking.widgets.table.TableColumnDescriptor
import docking.widgets.table.threaded.ThreadedTableModelStub
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
import lol.fairplay.ghidraapple.analysis.utilities.addColumn
import lol.fairplay.ghidraapple.analysis.utilities.setCallTarget

class ChooseMsgSendCalleeDialog(
    tool: Tool,
    private val program: Program,
    private val callsite: Address,
    selector: String?, // TODO: Later we can add a selector to filter the functions
) : DialogComponentProvider("Choose msgSend Callee", true, true, true, false) {
    private var functionsTable: GhidraFilterTable<Function>

    init {

        val matchingFunctionsTable = FunctionsForSelectorTable(tool, program.functionManager, selector)
        functionsTable = GhidraFilterTable(matchingFunctionsTable)

        rootPanel.add(functionsTable)

        // Add select button with action
        addDismissButton()
        addApplyButton()
    }

    override fun applyCallback() {
        // For simplicity, we support two scenarios here:
        // 1. If there is only one possible target being displayed, either due to filtering during doLoad
        // or due to user filtering, we automatically treat that as selected
        // 2. If there are multiple options, then the user needs to select a table entry
        val function: Function =
            if (functionsTable.model.modelData.size == 1) {
                functionsTable.model.modelData[0]
            } else {
                functionsTable.selectedRowObject ?: return
            }

        program.withTransaction<Exception>("ChooseMsgSendCalleeDialog") {
            program.referenceManager.setCallTarget(callsite, function, SourceType.USER_DEFINED)
        }
        close()
    }
}

class FunctionsForSelectorTable(
    tool: Tool,
    private val functionManager: FunctionManager,
    private val selector: String?,
) : ThreadedTableModelStub<Function>("", tool),
    ProgramTableModel {
    override fun createTableColumnDescriptor(): TableColumnDescriptor<Function> {
        val descriptor: TableColumnDescriptor<Function> = TableColumnDescriptor<Function>()
        descriptor.addColumn("Name", true) { it.name }
        descriptor.addColumn("Class", true) { it.parentNamespace.name }

        return descriptor
    }

    override fun doLoad(
        accumulator: Accumulator<Function>,
        monitor: TaskMonitor,
    ) {
        with(functionManager) {
            monitor.initialize(functionCount.toLong())
            getFunctions(true)
                .filter {
                    monitor.checkCancelled()
                    (selector == null || it.name == selector) && it.parentNamespace.name != "stub"
                }.forEach {
                    monitor.checkCancelled()
                    monitor.incrementProgress(1)
                    accumulator.add(it)
                }
        }
    }

    override fun getProgramLocation(
        modelRow: Int,
        modelColumn: Int,
    ): ProgramLocation {
        val func = getRowObject(modelRow)
        return ProgramLocation(func.program, func.entryPoint)
    }

    override fun getProgramSelection(modelRows: IntArray?): ProgramSelection = ProgramSelection()

    override fun getProgram(): Program = functionManager.program
}
