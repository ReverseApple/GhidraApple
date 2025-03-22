package lol.fairplay.ghidraapple.actions.mach.messaging

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.framework.cmd.BackgroundCommand
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.UnionDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.analysis.mach.messaging.MACH_CATEGORY_PATH_STRING
import lol.fairplay.ghidraapple.analysis.mach.messaging.MachMessageDataType
import lol.fairplay.ghidraapple.analysis.mach.messaging.MachMsgOptions

class MarkupMachMsgCall(
    private val highFunction: HighFunction,
    private val callSiteAddress: Address,
) : BackgroundCommand<Program>() {
    override fun getName(): String = "Mark mach_msg call at 0x$callSiteAddress"

    override fun applyTo(
        program: Program,
        monitor: TaskMonitor,
    ): Boolean {
        val callPCodeOp =
            highFunction
                .getPcodeOps(callSiteAddress)
                .asSequence()
                .toList()
                .firstOrNull { it.opcode == PcodeOp.CALL }
                ?: return false
        val callOptions =
            callPCodeOp.inputs[2]
                .takeIf { it.isConstant }
                ?.address
                ?.offset
                ?.let { MachMsgOptions.fromValue(it.toInt()) }
                ?: return false

        val messageSendSize =
            callPCodeOp.inputs[3]
                .takeIf { it.isConstant }
                ?.address
                ?.offset
                ?: return false

        val messageReceiveSize =
            callPCodeOp.inputs[4]
                .takeIf { it.isConstant }
                ?.address
                ?.offset
                ?: return false

        val sentMessageDataType =
            if (messageSendSize > 0 &&
                callOptions.contains(MachMsgOptions.MACH_SEND_MSG)
            ) {
                MachMessageDataType(
                    program.dataTypeManager,
                    "mach_msg_${callSiteAddress}_sent",
                    size = messageSendSize.toInt(),
                    isBeingReceived = false,
                )
            } else {
                null
            }

        val receivedMessageDataType =
            if (messageReceiveSize > 0 &&
                callOptions.contains(MachMsgOptions.MACH_RCV_MSG)
            ) {
                MachMessageDataType(
                    program.dataTypeManager,
                    "mach_msg_${callSiteAddress}_received",
                    size = messageReceiveSize.toInt(),
                    isBeingReceived = false,
                    sizeIncludesTrailer = true,
                )
            } else {
                null
            }

        val actualDataType: DataType =
            listOfNotNull(sentMessageDataType, receivedMessageDataType)
                .let {
                    if (it.size == 1) {
                        it.first()
                    } else {
                        UnionDataType("mach_msg_${callSiteAddress}_both")
                            .apply {
                                add(it[0], "sent", null)
                                add(it[1], "received", null)
                            }
                    }
                }.apply { categoryPath = CategoryPath(MACH_CATEGORY_PATH_STRING) }

        highFunction.function.stackFrame.createVariable(
            "mach_msg_$callSiteAddress",
            callPCodeOp.inputs[1]
                .def.inputs
                .first { it.isConstant }
                .offset
                .toInt(),
            actualDataType,
            SourceType.ANALYSIS,
        )

        return true
    }
}

class MarkupMachMsgCallAction(
    owner: String,
    private val tool: PluginTool,
) : DockingAction("Markup mach_msg Call", owner) {
    init {
        description = "Marks up the Mach messages being sent or received at this location"
        popupMenuData = MenuData(arrayOf("Markup mach_msg Call"), GhidraApplePluginPackage.Companion.PKG_NAME)
    }

    override fun isValidContext(context: ActionContext): Boolean = context is DecompilerActionContext

    override fun isEnabledForContext(context: ActionContext): Boolean {
        val typedContext = context as DecompilerActionContext
        if (typedContext.tokenAtCursor.toString() != "_mach_msg") return false

        val instructionAtLocation =
            typedContext.program.listing.getInstructionAt(typedContext.address)

        return instructionAtLocation.flowType.isCall
    }

    override fun actionPerformed(context: ActionContext) {
        val typedContext = context as DecompilerActionContext
        tool.executeBackgroundCommand(
            MarkupMachMsgCall(typedContext.highFunction, typedContext.address),
            typedContext.program,
        )
    }
}
