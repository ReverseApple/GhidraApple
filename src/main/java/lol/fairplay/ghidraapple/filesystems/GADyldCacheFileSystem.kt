package lol.fairplay.ghidraapple.filesystems

import ghidra.app.util.bin.ByteProvider
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
    factory = GFileSystemBaseFactory::class
)
class GADyldCacheFileSystem(fileSystemName: String?, provider: ByteProvider?) :
    DyldCacheFileSystem(fileSystemName, provider) {

        var platform: Dyld.Platform? = null
        var osVersion: Dyld.Version? = null

        override fun open(monitor: TaskMonitor?) {
            super.open(monitor)
            val rootHeader = this.splitDyldCache.getDyldCacheHeader(0)
            val rootHeaderDataType = rootHeader.toDataType() as StructureDataType? ?: return

            val fsByteProvider = this.provider // This is defined merely to avoid scope confusion in the below blocks.
            val headerOffsetInByteProvider = 0 // This is defined merely for explanatory benefit.

            // TODO: When Ghidra 11.4 returns (or whenever the [DyldCacheHeader] getters are implemented in a release),
            //  remove this function and replace uses of it with the implemented getters.
            fun getComponentBytes(componentName: String): ByteArray? {
                val component =
                    rootHeaderDataType.components.firstOrNull { it.fieldName == componentName } ?: return null
                return fsByteProvider.readBytes(
                    (headerOffsetInByteProvider + component.offset).toLong(),
                    component.length.toLong()
                )
            }

            this.platform = Dyld.Platform.getPlatform(
                // This is a little-endian integer that's never above 255, so getting just the first byte should be ok.
                getComponentBytes("platform")!![0].toUInt()
            )

            this.osVersion = Dyld.Version(
                ByteBuffer.wrap(getComponentBytes("osVersion")!!)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .int.toUInt()
            )
        }
}