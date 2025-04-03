package lol.fairplay.ghidraapple.windows

import docking.ActionContext
import docking.action.DockingAction
import docking.action.ToolBarData
import docking.widgets.table.TableColumnDescriptor
import ghidra.framework.plugintool.ComponentProviderAdapter
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.symbol.Reference
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection
import ghidra.util.datastruct.Accumulator
import ghidra.util.table.GhidraFilterTable
import ghidra.util.table.GhidraProgramTableModel
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_ALLOC
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCTypeInjectorAnalyzer.Companion.ALLOC_DATA
import lol.fairplay.ghidraapple.analysis.utilities.addColumn
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.getFunctionsWithAnyTag
import lol.fairplay.ghidraapple.db.DataBaseLayer
import lol.fairplay.ghidraapple.db.ObjectiveCClass
import lol.fairplay.ghidraapple.plugins.ObjectiveCDynamicDispatchPlugin
import resources.Icons
import javax.swing.JComponent

data class AllocSiteData(
    val reference: Reference,
    val calledRuntimeFunction: Function,
    val classData: ObjectiveCClass?,
) {
    companion object {
        fun from(
            program: Program,
            reference: Reference,
        ): AllocSiteData {
            //
            val clsAddr =
                program.usrPropertyManager
                    .getLongPropertyMap(ALLOC_DATA)
                    ?.get(reference.fromAddress)
                    ?.let(program::address)
            val classData = clsAddr?.let { DataBaseLayer(program).getClassForAddress(it) }

            return AllocSiteData(reference, program.functionManager.getFunctionAt(reference.toAddress), classData)
        }
    }
}

class AllocViewerComponent(
    tool: PluginTool,
) : ComponentProviderAdapter(tool, "Objc: Alloc Site Viewer", GhidraApplePluginPackage.PKG_NAME) {
//    private var refreshAction: DockingAction
    private val tableModel = AllocTable(tool)
    private val tablePanel = GhidraFilterTable(tableModel)

    init {
        icon = GhidraApplePluginPackage.OBJC_ICON
    }

    fun install(tool: PluginTool): AllocViewerComponent {
        tablePanel.installNavigation(tool)
        val refreshAction =
            object : DockingAction("Refresh", ObjectiveCDynamicDispatchPlugin::class.simpleName) {
                override fun actionPerformed(context: ActionContext) {
                    tableModel.reload()
                }
            }
        refreshAction.setToolBarData(ToolBarData(Icons.REFRESH_ICON))
        refreshAction.setDescription(
            "<html>Push at any time to refresh the current table of references.<br>",
        )
        tool.addComponentProvider(this, false)
        tool.addLocalAction(this, refreshAction)
        return this
    }

    fun updateProgram(program: Program) {
        tableModel.program = program
        tableModel.reload()
    }

    override fun getComponent(): JComponent = tablePanel
}

class AllocTable(
    pluginTool: PluginTool,
) : GhidraProgramTableModel<AllocSiteData>("Alloc Site Table", pluginTool, null, null) {
    override fun createTableColumnDescriptor(): TableColumnDescriptor<AllocSiteData> {
        val descriptor = TableColumnDescriptor<AllocSiteData>()
        descriptor.addColumn("Address", true, Address::class.java) { it.reference.fromAddress }
        descriptor.addColumn("Class Address", true, Address::class.java) { it.classData?.classStructLocation }
        descriptor.addColumn("Class Name", true, String::class.java) { it.classData?.name }
        descriptor.addColumn("Is External Class", true, Boolean::class.java) {
            it.classData?.classStructLocation?.let(program.memory::isExternalBlockAddress)
        }
        descriptor.addColumn("Runtime Function", true, Function::class.java) { it.calledRuntimeFunction }
        descriptor.addColumn("Override", true, String::class.java) {
            val sym = program.symbolTable.getPrimarySymbol(it.reference.fromAddress)
            sym?.let(HighFunctionDBUtil::readOverride)?.dataType?.displayName
        }

        return descriptor
    }

    override fun doLoad(
        accumulator: Accumulator<AllocSiteData>,
        monitor: TaskMonitor,
    ) {
        if (program == null) return
        val callsites =
            program.functionManager
                .getFunctionsWithAnyTag(OBJC_ALLOC)
                .flatMap { program.referenceManager.getReferencesTo(it.entryPoint) }
        monitor.maximum = callsites.size.toLong()
        callsites.asSequence()
            .onEach { monitor.checkCancelled() }
            .onEach { monitor.incrementProgress(1) }
            .map { AllocSiteData.from(program, it) }
            .sortedBy { it.reference.fromAddress }
            .forEach { accumulator.add(it) }
    }

    override fun getProgramLocation(
        modelRow: Int,
        modelColumn: Int,
    ): ProgramLocation {
        getRowObject(modelRow).let {
            return ProgramLocation(program, it.reference.fromAddress)
        }
    }

    override fun getProgramSelection(modelRows: IntArray): ProgramSelection {
        val addressSet = AddressSet()
        modelRows.forEach {
            addressSet.add(getRowObject(it).reference.fromAddress)
        }
        return ProgramSelection(addressSet)
    }
}
