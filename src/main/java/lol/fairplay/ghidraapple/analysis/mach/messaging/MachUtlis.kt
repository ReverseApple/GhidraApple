package lol.fairplay.ghidraapple.analysis.mach.messaging

import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility
import ghidra.program.model.data.FileDataTypeManager

val macOSXDataTypeManager =
    FileDataTypeManager.openFileArchive(DataTypeArchiveUtility.findArchiveFile("mac_osx"), false)!!

val machMessageHeaderDataType = macOSXDataTypeManager.getDataType("/message.h/mach_msg_header_t")!!
val machMessageBodyDataType = macOSXDataTypeManager.getDataType("/message.h/mach_msg_body_t")!!
val machMessageMaxTrailerDataType = macOSXDataTypeManager.getDataType("/message.h/mach_msg_max_trailer_t")!!

val machMessagePortDescriptorDataType =
    macOSXDataTypeManager.getDataType("/message.h/mach_msg_port_descriptor_t")!!
val machMessageOOLDescriptorDataType =
    macOSXDataTypeManager.getDataType("/message.h/mach_msg_ool_descriptor_t")!!
val machMessageOOLPortsDataType =
    macOSXDataTypeManager.getDataType("/message.h/mach_msg_ool_ports_descriptor_t")!!

enum class MachMsgOptions(
    val value: Int,
) {
    MACH_SEND_MSG(0x00000001),
    MACH_RCV_MSG(0x00000002),
    ;

    companion object {
        fun fromValue(value: Int): List<MachMsgOptions> =
            MachMsgOptions.entries.filter { flag ->
                value and flag.value == flag.value
            }
    }
}
