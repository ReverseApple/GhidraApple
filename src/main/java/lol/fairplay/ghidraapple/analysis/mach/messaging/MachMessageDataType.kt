package lol.fairplay.ghidraapple.analysis.mach.messaging

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.StructureDataType

const val MACH_CATEGORY_PATH_STRING = "/GA_MACH"

enum class MachMessageDescriptorType(
    val value: Int,
    val dataType: DataType,
) {
    MACH_MSG_PORT_DESCRIPTOR(0, machMessagePortDescriptorDataType),
    MACH_MSG_OOL_DESCRIPTOR(1, machMessageOOLDescriptorDataType),
    MACH_MSG_OOL_PORTS_DESCRIPTOR(2, machMessageOOLPortsDataType),
    MACH_MSG_OOL_VOLATILE_DESCRIPTOR(3, machMessageOOLDescriptorDataType),
    // TODO: The structure for the below descriptor type doesn't exist in the macOS data type manager
    //  built into Ghidra. I have yet to come across something that uses this descriptor type. Should
    //  we implement it ourselves or just ignore its existence?
//    MACH_MSG_GUARDED_PORT_DESCRIPTOR(4, ...),
    ;

    companion object {
        fun fromValue(value: Int): MachMessageDescriptorType? = entries.firstOrNull { it.value == value }
    }
}

class MachMessageDataType(
    dataTypeManager: DataTypeManager,
    name: String,
    descriptors: List<MachMessageDescriptorType>? = null,
    size: Int =
        machMessageHeaderDataType.length +
            (
                descriptors?.let {
                    machMessageBodyDataType.length
                    +it.fold(0) { totalSize, descriptor -> totalSize + descriptor.dataType.length }
                } ?: 0
            ),
    isBeingReceived: Boolean = false,
    sizeIncludesTrailer: Boolean = false,
) : StructureDataType(
        CategoryPath(MACH_CATEGORY_PATH_STRING),
        name,
        0,
        dataTypeManager,
    ) {
    init {
        add(machMessageHeaderDataType, "header", null)
        descriptors?.let {
            add(machMessageBodyDataType, "body", null)
            it.forEach { add(it.dataType) }
        }
        val remainingBytes =
            (size - this.length)
                .let { if (isBeingReceived && sizeIncludesTrailer) it - machMessageMaxTrailerDataType.length else it }
        when {
            remainingBytes < 0 -> throw IllegalStateException("Size must be at least as long as mandatory fields.")
            remainingBytes > 0 -> {
                repeat(remainingBytes) { add(DEFAULT, "", null) }
                if (isBeingReceived) {
                    // If the passed-in size included the trailer, the alignment bytes
                    //   should be already accounted for.
                    if (!sizeIncludesTrailer) {
                        val alignmentBytes = this.alignedLength - this.length
                        repeat(alignmentBytes) { add(DEFAULT, "", null) }
                    }
                    add(machMessageMaxTrailerDataType, "trailer", null)
                }
            }
        }
    }
}
