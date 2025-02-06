package lol.fairplay.ghidraapple.windows

import docking.ActionContext
import docking.action.DockingAction
import docking.action.ToolBarData
import docking.widgets.table.TableColumnDescriptor
import ghidra.framework.plugintool.ComponentProviderAdapter
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.DataType
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
import lol.fairplay.ghidraapple.analysis.utilities.addColumn
import lol.fairplay.ghidraapple.analysis.utilities.getFunctionsWithAnyTag
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import lol.fairplay.ghidraapple.db.DataBaseLayer
import lol.fairplay.ghidraapple.plugins.ObjectiveCDynamicDispatchPlugin
import resources.Icons
import javax.swing.JComponent

data class DynamicDispatchCallsiteData(
    val reference: Reference,
    val calledRuntimeFunction: Function?,
    val implementation: Function?,
    val selector: String?,
    val typeBoundName: String?,
    val typeBound: DataType?,
) {
    companion object {
        fun from(
            program: Program,
            reference: Reference,
        ): DynamicDispatchCallsiteData {
            val dataBase = DataBaseLayer(program)
            val primaryRef = program.referenceManager.getPrimaryReferenceFrom(reference.fromAddress, 0)
            val impl =
                if (primaryRef != null && primaryRef != reference) {
                    program.functionManager.getFunctionAt(primaryRef.toAddress)
                } else {
                    null
                }
            val runtimeFunction = program.functionManager.getFunctionAt(reference.toAddress)
            val selector: String? =
                if (runtimeFunction.hasTag(OBJC_TRAMPOLINE)) {
                    runtimeFunction.name
                } else {
                    dataBase.getSelectorAtCallsite(reference.fromAddress)
                }
            val dataType = dataBase.getTypeBoundAtCallsite(reference.fromAddress)
            return DynamicDispatchCallsiteData(
                reference,
                runtimeFunction,
                impl,
                selector,
                dataType?.name,
                dataType,
            )
        }
    }
}

class DynamicDispatchComponent(
    tool: PluginTool,
) : ComponentProviderAdapter(tool, "Objc: Dynamic Dispatch Viewer", GhidraApplePluginPackage.PKG_NAME) {
    private val tableModel = DynamicDispatchTable(tool)
    private val tablePanel = GhidraFilterTable(tableModel)

    init {
        icon = GhidraApplePluginPackage.OBJC_ICON
    }

    fun updateProgram(program: Program) {
        tableModel.program = program
        tableModel.reload()
    }

    fun install(tool: PluginTool): DynamicDispatchComponent {
        tool.addComponentProvider(this, false)
        tablePanel.installNavigation(tool)
        val refreshAction =
            object : DockingAction("Refresh", ObjectiveCDynamicDispatchPlugin::class.simpleName) {
                override fun actionPerformed(context: ActionContext) {
                    tableModel.refresh()
                    tableModel.reload()
                }
            }
        refreshAction.setToolBarData(ToolBarData(Icons.REFRESH_ICON))
        refreshAction.setDescription(
            "<html>Push at any time to refresh the current table of references.<br>",
        )
        tool.addLocalAction(this, refreshAction)
        return this
    }

    override fun getComponent(): JComponent = tablePanel
}

class DynamicDispatchTable(
    pluginTool: PluginTool,
) : GhidraProgramTableModel<DynamicDispatchCallsiteData>("Dynamic Dispatch Table", pluginTool, null, null) {
    override fun createTableColumnDescriptor(): TableColumnDescriptor<DynamicDispatchCallsiteData> {
        val descriptor = TableColumnDescriptor<DynamicDispatchCallsiteData>()
        descriptor.addColumn("Address", true, Address::class.java) { it.reference.fromAddress }
//        descriptor.addColumn("Receiver Type", true, String::class.java) { it }
        descriptor.addColumn("Static Receiver", true, String::class.java) {
            val receiver = DataBaseLayer(program).getStaticReceiverAddrAtCallsite(it.reference.fromAddress)
            if (receiver != null) {
                program.symbolTable
                    .getPrimarySymbol(receiver.toDefaultAddressSpace(program))
                    ?.toString()
                    ?.removePrefix("_OBJC_CLASS_\$_")
            } else {
                null
            }
        }

        descriptor.addColumn("Static Receiver (Addr)", false, String::class.java) {
            DataBaseLayer(program).getStaticReceiverAddrAtCallsite(it.reference.fromAddress)?.toString()
        }

        descriptor.addColumn("Intra-Procedural Alloc", true, String::class.java) {
            val receiver = DataBaseLayer(program).getAllocedReceiverAddrAtCallsite(it.reference.fromAddress)
            if (receiver != null) {
                program.symbolTable.getPrimarySymbol(receiver.toDefaultAddressSpace(program))?.toString()
            } else {
                null
            }
        }
        descriptor.addColumn("Intra-Procedural Alloc (Addr)", false, String::class.java) {
            DataBaseLayer(program).getAllocedReceiverAddrAtCallsite(it.reference.fromAddress)?.toString()
        }
        descriptor.addColumn("Recv Type Bound", true, String::class.java) {
            it.typeBound?.toString()
        }

        descriptor.addColumn("Recv Type Bound Name", true, String::class.java) {
            it.typeBoundName
        }

//        descriptor.addColumn("Recv Type Bound ID", true, Long::class.java) {
//            it.typeBoundId
//        }

        descriptor.addColumn("Selector", true, String::class.java) { it.selector }
        descriptor.addColumn("Implementation", true, Function::class.java) { it.implementation }
        descriptor.addColumn("Is Trampoline", true, Boolean::class.java) {
            it.calledRuntimeFunction
                ?.tags
                ?.map { tag -> tag.name }
                ?.contains(OBJC_TRAMPOLINE)
        }
        descriptor.addColumn("Runtime Function", true, Function::class.java) { it.calledRuntimeFunction }

        return descriptor
    }

    override fun doLoad(
        accumulator: Accumulator<DynamicDispatchCallsiteData>,
        monitor: TaskMonitor,
    ) {
        if (program == null) return
        val data =
            program.functionManager
                .getFunctionsWithAnyTag(OBJC_DISPATCH_SELECTOR, OBJC_DISPATCH_CLASS, OBJC_TRAMPOLINE)
                .asSequence()
                .takeWhile { !monitor.isCancelled }
                .flatMap { program.referenceManager.getReferencesTo(it.entryPoint) }
                .filter { it.referenceType.isCall }
                .filterNot { program.functionManager.getFunctionContaining(it.fromAddress)?.hasTag(OBJC_TRAMPOLINE) ?: false }
                .map { DynamicDispatchCallsiteData.from(program, it) }
                .toSortedSet(compareBy { it.reference.fromAddress })
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

    override fun getProgramSelection(modelRows: IntArray): ProgramSelection {
        val addressSet = AddressSet()
        modelRows.forEach {
            addressSet.add(getRowObject(it).reference.fromAddress)
        }
        return ProgramSelection(addressSet)
    }
}
