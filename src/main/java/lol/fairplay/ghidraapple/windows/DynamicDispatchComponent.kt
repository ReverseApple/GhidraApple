package lol.fairplay.ghidraapple.windows

import docking.widgets.table.TableColumnDescriptor
import ghidra.framework.plugintool.ComponentProviderAdapter
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Reference
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection
import ghidra.util.datastruct.Accumulator
import ghidra.util.table.GhidraFilterTable
import ghidra.util.table.GhidraProgramTableModel
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_CLASS
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_SELECTOR
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_TRAMPOLINE
import lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch.OCSelectorAnalyzer.Companion.SELECTOR_DATA
import lol.fairplay.ghidraapple.analysis.utilities.addColumn
import lol.fairplay.ghidraapple.analysis.utilities.getFunctionsWithAnyTag
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import javax.swing.JComponent

data class DynamicDispatchCallsiteData(
    val reference: Reference,
    val calledRuntimeFunction: Function?,
    val implementation: Function?,
    val selector: String?,
) {
    companion object {
        fun from(
            program: Program,
            reference: Reference,
        ): DynamicDispatchCallsiteData =
            DynamicDispatchCallsiteData(
                reference,
                program.functionManager.getFunctionAt(reference.toAddress),
                null,
                program.usrPropertyManager.getStringPropertyMap(SELECTOR_DATA)?.get(reference.fromAddress),
            )
    }
}

class DynamicDispatchComponent(
    tool: PluginTool,
) : ComponentProviderAdapter(tool, "Dynamic Dispatch Viewer", GhidraApplePluginPackage.PKG_NAME) {
    private val tableModel = DynamicDispatchTable(tool)
    private val tablePanel = GhidraFilterTable(tableModel)

    init {
        tablePanel.installNavigation(tool)
    }

    fun updateProgram(program: Program) {
        tableModel.program = program
        tableModel.reload()
    }

    override fun getComponent(): JComponent = tablePanel
}

class DynamicDispatchTable(
    pluginTool: PluginTool,
) : GhidraProgramTableModel<DynamicDispatchCallsiteData>("Dynamic Dispatch Table", pluginTool, null, null) {
    override fun createTableColumnDescriptor(): TableColumnDescriptor<DynamicDispatchCallsiteData> {
        val descriptor = TableColumnDescriptor<DynamicDispatchCallsiteData>()
        descriptor.addColumn("Address", true) { it.reference.fromAddress }
        descriptor.addColumn("Class", true) { null }
        descriptor.addColumn("Selector", true) { it.selector }
        descriptor.addColumn("Implementation", true) { it.implementation }
        descriptor.addColumn("Is Trampoline", true) {
            it.calledRuntimeFunction
                ?.tags
                ?.map { tag -> tag.name }
                ?.contains(OBJC_TRAMPOLINE)
        }
        descriptor.addColumn("Runtime Function", true) { it.calledRuntimeFunction }

        return descriptor
    }

    override fun doLoad(
        accumulator: Accumulator<DynamicDispatchCallsiteData>,
        monitor: TaskMonitor,
    ) {
        if (program == null) return
        val data =
            program.functionManager
                .getFunctionsWithAnyTag(OBJC_DISPATCH_SELECTOR, OBJC_DISPATCH_CLASS)
                .flatMap { program.referenceManager.getReferencesTo(it.entryPoint) }
                .filterNot { program.functionManager.getFunctionContaining(it.fromAddress)?.hasTag(OBJC_TRAMPOLINE) ?: false }
                .map { DynamicDispatchCallsiteData.from(program, it) }
                .toSet()
        accumulator.addAll(data)
    }

    override fun getProgramLocation(
        modelRow: Int,
        modelColumn: Int,
    ): ProgramLocation {
        getRowObject(modelRow).let {
            return ProgramLocation(program, it.reference.fromAddress)
        }
    }

    override fun getProgramSelection(modelRows: IntArray?): ProgramSelection? = null
}
