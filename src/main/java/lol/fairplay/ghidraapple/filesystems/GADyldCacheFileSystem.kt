package lol.fairplay.ghidraapple.filesystems

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo
import ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem
import ghidra.formats.gfilesystem.annotations.FileSystemInfo
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory
import ghidra.program.model.data.StructureDataType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.core.objc.modelling.Dyld
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.reflect.KClass
import kotlin.reflect.cast

@FileSystemInfo(
    type = "ga${DyldCacheFileSystem.DYLD_CACHE_FSTYPE}",
    description = "(GhidraApple) Dyld Cache",
    factory = GFileSystemBaseFactory::class,
)
class GADyldCacheFileSystem(
    fileSystemName: String?,
    provider: ByteProvider?,
) : DyldCacheFileSystem(fileSystemName, provider) {
    val rootHeader: DyldCacheHeader
        get() = this.splitDyldCache?.getDyldCacheHeader(0) ?: throw IOException("Failed to get root header.")
    var platform: Dyld.Platform? = null
    var osVersion: Dyld.Version? = null

    companion object {
        const val ROOT_HEADER_OFFSET_IN_BYTE_PROVIDER = 0L // This is defined merely for explanatory benefit.
    }

    // TODO: Remove this when no longer needed.
    fun getMappings(): Map<DyldCacheMappingInfo, ByteArray> {
        val map = mutableMapOf<DyldCacheMappingInfo, ByteArray>()
        for (mappingInfo in this.rootHeader.mappingInfos) {
            map[mappingInfo] = this.provider.readBytes(mappingInfo.fileOffset, mappingInfo.size)
        }
        return map
    }

    private fun <T : Any> getComponentValue(
        componentName: String,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
        type: KClass<T>,
    ): T {
        val byteBuffer = ByteBuffer.wrap(getComponentBytes(componentName)!!).order(byteOrder)
        return type.cast(
            when (type) {
                Long::class -> byteBuffer.long
                ULong::class -> byteBuffer.long.toULong()
                Int::class -> byteBuffer.int
                UInt::class -> byteBuffer.int.toUInt()
                Short::class -> byteBuffer.short
                UShort::class -> byteBuffer.short.toUShort()
                Float::class -> byteBuffer.float
                Double::class -> byteBuffer.double
                else -> throw IllegalArgumentException("Unsupported type: ${type.simpleName}")
            },
        )
    }

    // TODO: When Ghidra 11.4 returns (or whenever the [DyldCacheHeader] getters are implemented in a release),
    //  remove this function (and helper function(s)) and replace uses of them with the implemented getters.
    private fun getComponentBytes(componentName: String): ByteArray? {
        val rootHeaderDataType = this.rootHeader.toDataType() as StructureDataType? ?: return null
        val component =
            rootHeaderDataType.components.firstOrNull { it.fieldName == componentName } ?: return null
        return this.provider.readBytes(
            ROOT_HEADER_OFFSET_IN_BYTE_PROVIDER + component.offset,
            component.length.toLong(),
        )
    }

    fun readMappedCString(start: Long): String? {
        for (mappingInfo in this.rootHeader.mappingInfos) {
            if (start < mappingInfo.address || start > (mappingInfo.address + mappingInfo.size)) continue
            var string = ""
            var currentAddress = mappingInfo.fileOffset + (start - mappingInfo.address)
            string_builder@ do {
                val byte = this.provider.readByte(currentAddress)
                if (byte == 0x00.toByte()) break@string_builder
                string += byte.toInt().toChar()
                currentAddress++
            } while // Don't keep reading outside mapped sections.
            (currentAddress <= (mappingInfo.address + mappingInfo.size))
            return string.takeIf { it != "" }
        }
        return null // No match.
    }

    override fun open(monitor: TaskMonitor?) {
        super.open(monitor)
        this.platform = Dyld.Platform.getPlatform(getComponentValue(componentName = "platform", type = Int::class).toUInt())
        this.osVersion = Dyld.Version(getComponentValue(componentName = "osVersion", type = Int::class).toUInt())
    }
}
