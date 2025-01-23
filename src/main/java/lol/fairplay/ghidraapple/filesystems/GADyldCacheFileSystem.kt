package lol.fairplay.ghidraapple.filesystems

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader
import ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem
import ghidra.formats.gfilesystem.annotations.FileSystemInfo
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory
import ghidra.program.model.data.StructureDataType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.core.objc.modelling.Dyld
import java.nio.ByteBuffer
import java.nio.ByteOrder

@FileSystemInfo(
    type = "ga${DyldCacheFileSystem.DYLD_CACHE_FSTYPE}",
    description = "(GhidraApple) Dyld Cache",
    factory = GFileSystemBaseFactory::class,
)
class GADyldCacheFileSystem(
    fileSystemName: String?,
    provider: ByteProvider?,
) : DyldCacheFileSystem(fileSystemName, provider) {
    private var rootHeader: DyldCacheHeader? = null
    private val rootHeaderOffsetInByteProvider: Long?
        get() = rootHeader?.baseAddress
    var platform: Dyld.Platform? = null
    var osVersion: Dyld.Version? = null

    // TODO: When Ghidra 11.4 returns (or whenever the [DyldCacheHeader] getters are implemented in a release),
    //  remove this function and replace uses of it with the implemented getters.
    private fun getComponentBytes(componentName: String): ByteArray? {
        if (this.rootHeader == null) this.rootHeader = this.splitDyldCache.getDyldCacheHeader(0) ?: return null
        val rootHeaderDataType = this.rootHeader!!.toDataType() as StructureDataType? ?: return null
        val component =
            rootHeaderDataType.components.firstOrNull { it.fieldName == componentName } ?: return null
        return this.provider.readBytes(
            rootHeaderOffsetInByteProvider!! + component.offset,
            component.length.toLong(),
        )
    }

    override fun open(monitor: TaskMonitor?) {
        super.open(monitor)

        this.platform =
            Dyld.Platform.getPlatform(
                // This is a little-endian integer that's never above 255, so getting just the first byte should be ok.
                getComponentBytes("platform")!![0].toUInt(),
            )

        this.osVersion =
            Dyld.Version(
                ByteBuffer
                    .wrap(getComponentBytes("osVersion")!!)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .int
                    .toUInt(),
            )
    }

    private fun getOptimizationsHeaderBytes(): ByteArray? {
        val optimizationsHeaderOffset =
            ByteBuffer
                .wrap(getComponentBytes("objcOptsOffset")!!)
                .order(ByteOrder.LITTLE_ENDIAN)
                .long
        val optimizationsHeaderLength =
            ByteBuffer
                .wrap(getComponentBytes("objcOptsSize")!!)
                .order(ByteOrder.LITTLE_ENDIAN)
                .long
        val actualOffset = rootHeaderOffsetInByteProvider!! + optimizationsHeaderOffset
        if (actualOffset >= this.provider.length()) return null
        return this.provider.readBytes(actualOffset, optimizationsHeaderLength)
    }
}
