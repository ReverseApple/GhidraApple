package lol.fairplay.ghidraapple.windows

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import docking.action.ToolBarData
import docking.widgets.table.TableColumnDescriptor
import ghidra.framework.plugintool.ComponentProviderAdapter
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.DataType
import ghidra.program.model.lang.Register
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
import lol.fairplay.ghidraapple.actions.CreateObjCMethodThunkCmd
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_CLASS
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_DISPATCH_SELECTOR
import lol.fairplay.ghidraapple.analysis.passes.ObjectiveCDispatchTagAnalyzer.Companion.OBJC_TRAMPOLINE
import lol.fairplay.ghidraapple.analysis.utilities.addColumn
import lol.fairplay.ghidraapple.analysis.utilities.getFunctionsWithAnyTag
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import lol.fairplay.ghidraapple.db.DataBaseLayer
import lol.fairplay.ghidraapple.db.ObjectiveCClass
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
    val staticOCClass: ObjectiveCClass?,
    val allocedOCClass: ObjectiveCClass?,
    val paramReceiver: Register?,
) {
    companion object {
        fun from(
            program: Program,
            reference: Reference,
        ): DynamicDispatchCallsiteData {
            val dataBase = DataBaseLayer(program)
            return from(dataBase, program, reference)
        }
        fun from(dataBase: DataBaseLayer, program: Program, reference: Reference): DynamicDispatchCallsiteData {
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
            val staticOcClass = dataBase.getStaticReceiverClassAtCallsite(reference.fromAddress)
            val allocedOcClass = dataBase.getAllocedReceiverClassAtCallsite(reference.fromAddress)
            val paramReceiver = dataBase.getParamReceiverAtCallsite(reference.fromAddress)
            return DynamicDispatchCallsiteData(
                reference,
                runtimeFunction,
                impl,
                selector,
                dataType?.name,
                dataType,
                staticOcClass,
                allocedOcClass,
                paramReceiver
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


        val createThunkAction =
            object : DockingAction("Create Thunk", ObjectiveCDynamicDispatchPlugin::class.simpleName) {
                init {
                    popupMenuData = MenuData(arrayOf("Create Thunk"), GhidraApplePluginPackage.PKG_NAME)
                }

                override fun isEnabledForContext(context: ActionContext?): Boolean {
                    return tablePanel.selectedRowObject.let {
                        val cls = it.staticOCClass ?: it.allocedOCClass
                        return it.implementation == null && cls != null && it.selector != null
                    }
                }

                override fun actionPerformed(ctx: ActionContext) {
                    val row = tablePanel.selectedRowObject
                    val cls: ObjectiveCClass = row.staticOCClass ?: row.allocedOCClass!!

                    tool.executeBackgroundCommand(
                        CreateObjCMethodThunkCmd(
                            cls,
                            row.selector!!,
                        ), tableModel.program
                    )
                }

            }
        tool.addLocalAction(this, createThunkAction)

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
        descriptor.addColumn("Caller Function", true, Function::class.java) {
            program.functionManager.getFunctionContaining(it.reference.fromAddress)
        }

        descriptor.addColumn("Type Result", true, String::class.java) {
            it.staticOCClass?.name ?: it.allocedOCClass?.name ?: it.typeBoundName
        }
        descriptor.addColumn("Local Class", true, Boolean::class.java) {
            (it.staticOCClass ?: it.allocedOCClass)?.isPartOfProgram(program) ?:
            // If the type bound struct has a size greater than the empty struct, it's a local class, because we don't
            // know (or even care) about the size of external classes
            (it.typeBound?.isZeroLength == false)
        }

        descriptor.addColumn("Static Receiver", true, String::class.java) { it.staticOCClass?.name }

        descriptor.addColumn("Static Receiver (Addr)", false, Address::class.java) {
            it.staticOCClass?.classStructLocation
        }

        descriptor.addColumn("Intra-Procedural Alloc", true, String::class.java) { it.allocedOCClass?.name }
        descriptor.addColumn("Intra-Procedural Alloc (Addr)", false, Address::class.java) {
            it.allocedOCClass?.classStructLocation
        }

        descriptor.addColumn("Parameter Receiver", true, String::class.java) {
            it.paramReceiver?.name
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
        val callsites =
            program.functionManager
                .getFunctionsWithAnyTag(OBJC_DISPATCH_SELECTOR, OBJC_DISPATCH_CLASS, OBJC_TRAMPOLINE)
                .asSequence()
                .flatMap { program.referenceManager.getReferencesTo(it.entryPoint) }
                .filter { it.referenceType.isCall }
                .filterNot { program.functionManager.getFunctionContaining(it.fromAddress)?.hasTag(OBJC_TRAMPOLINE) ?: false }
        monitor.maximum = callsites.count().toLong()
        val db = DataBaseLayer(program)
        callsites
            .onEach {
                monitor.checkCancelled()
                monitor.incrementProgress(1)
            }
            .map { DynamicDispatchCallsiteData.from(db, program, it) }
//            .toSortedSet(compareBy { it.reference.fromAddress })
            .forEach(accumulator::add)
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
