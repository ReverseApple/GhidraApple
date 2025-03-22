package lol.fairplay.ghidraapple.actions.mach.mig

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.context.ListingActionContext
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.util.bin.format.macho.SectionNames
import ghidra.framework.cmd.BackgroundCommand
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.mach.messaging.mig.MIGSubsystem
import lol.fairplay.ghidraapple.analysis.mach.messaging.mig.isMIGServerRoutine
import lol.fairplay.ghidraapple.analysis.utilities.getAddressOfPointerAtAddress
import lol.fairplay.ghidraapple.analysis.utilities.getPotentiallyUndefinedFunctionAtAddress

class MarkMIGSubsystem(
    val address: Address,
) : BackgroundCommand<Program>() {
    override fun getName(): String = "Mark MIG Subsystem at 0x$address"

    private var errorMsg: String? = null

    override fun getStatusMsg(): String? = errorMsg

    override fun applyTo(
        program: Program,
        monitor: TaskMonitor,
    ): Boolean {
        val subsystem = MIGSubsystem(program, address)
        program.withTransaction<Exception>("Mark MIG Subsystem at 0x$address") {
            DataUtilities.createData(
                program,
                address,
                subsystem.toDataType(),
                -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
            subsystem.markup(false)
        }
        return true
    }
}

class MarkAsMIGSubsystemAction(
    owner: String,
    private val tool: PluginTool,
) : DockingAction(TITLE, owner) {
    companion object {
        const val TITLE = "Mark As MIG Subsystem"
    }

    init {
        description = "Mark the current location as a MIG subsystem"
        popupMenuData = MenuData(arrayOf(TITLE), GhidraApplePluginPackage.Companion.PKG_NAME)
    }

    init {
        popupMenuData = MenuData(arrayOf(this.name), GhidraApplePluginPackage.Companion.PKG_NAME)
    }

    override fun isValidContext(context: ActionContext): Boolean = context is ListingActionContext

    override fun actionPerformed(context: ActionContext) {
        val typedContext = context as ListingActionContext
        tool.executeBackgroundCommand<Program>(MarkMIGSubsystem(typedContext.address), typedContext.program)
    }

    override fun isEnabledForContext(context: ActionContext?): Boolean {
        val typedContext =
            context as? ProgramLocationActionContext ?: return false

        if (typedContext.program.memory
                .getBlock(typedContext.address)
                .name != SectionNames.DATA_CONST
        ) {
            return false
        }

        typedContext.program
            .getAddressOfPointerAtAddress(typedContext.address)
            ?.let { typedContext.program.getPotentiallyUndefinedFunctionAtAddress(it) }
            ?.takeIf { it.isMIGServerRoutine() }
            ?: return false

        return true
    }
}
