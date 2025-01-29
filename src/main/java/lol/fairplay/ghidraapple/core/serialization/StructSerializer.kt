package lol.fairplay.ghidraapple.core.serialization

import ghidra.program.model.data.StructureDataType
import java.io.IOException

class StructSerializer(
    private val dataType: StructureDataType,
    private val offsetInBytes: Int = 0,
) {
    val bytes = ByteArray(dataType.length)

    private fun getComponentByName(componentName: String) =
        dataType.components
            .firstOrNull { it.fieldName == componentName }

    fun getComponentBytes(componentName: String): ByteArray? {
        val component = getComponentByName(componentName) ?: return null
        val fullOffset = (offsetInBytes + component.offset)
        return this.bytes.copyOfRange(fullOffset, fullOffset + component.length)
    }

    fun setComponentBytes(
        componentName: String,
        byteArray: ByteArray,
    ) {
        val component =
            getComponentByName(componentName)
                ?: throw IOException("Component \"$componentName\" not found!")
        byteArray.copyInto(bytes, offsetInBytes + component.offset)
    }
}
