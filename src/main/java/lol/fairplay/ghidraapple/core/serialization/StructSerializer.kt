package lol.fairplay.ghidraapple.core.serialization

import ghidra.program.model.data.StructureDataType
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.reflect.cast

class StructSerializer(
    private val dataType: StructureDataType,
    var bytes: ByteArray = ByteArray(dataType.length),
    private val offsetInBytes: Int = 0,
) {
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

    inline fun <reified T : Any> getComponentValue(
        componentName: String,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ): T {
        val byteBuffer = ByteBuffer.wrap(getComponentBytes(componentName)!!).order(byteOrder)
        return T::class.cast(
            when (T::class) {
                Long::class -> byteBuffer.long
                ULong::class -> byteBuffer.long.toULong()
                Int::class -> byteBuffer.int
                UInt::class -> byteBuffer.int.toUInt()
                Short::class -> byteBuffer.short
                UShort::class -> byteBuffer.short.toUShort()
                Float::class -> byteBuffer.float
                Double::class -> byteBuffer.double
                else -> throw IllegalArgumentException("Unsupported type: ${T::class.simpleName}")
            },
        )
    }
}
