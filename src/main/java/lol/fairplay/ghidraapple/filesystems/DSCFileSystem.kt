package lol.fairplay.ghidraapple.filesystems

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.DyldCacheUtils
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache
import ghidra.formats.gfilesystem.GFile
import ghidra.formats.gfilesystem.GFileImpl
import ghidra.formats.gfilesystem.GFileSystem
import ghidra.formats.gfilesystem.GFileSystemBase
import ghidra.formats.gfilesystem.annotations.FileSystemInfo
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.dyld.DSCExtractor
import lol.fairplay.ghidraapple.dyld.MappedDSCByteProvider
import java.io.IOException

/**
 * A dyld (shared) cache expressed as a [GFileSystem].
 */
@FileSystemInfo(
    type = "dsc",
    description = "dyld Shared Cache",
    factory = GFileSystemBaseFactory::class,
)
class DSCFileSystem(
    fileSystemName: String,
    provider: ByteProvider,
) : GFileSystemBase(fileSystemName, provider) {
    /**
     * A [ByteProvider] for the cache, mapped into a representation of virtual memory.
     */
    var mappedCacheProvider: MappedDSCByteProvider? = null

    /**
     * A map between actual dylib's in the cache and their addresses.
     */
    private val fileAddressMap = mutableMapOf<GFile, Long>()

    /**
     * A set of all files and directories in the cache file system.
     */
    private val allFilesAndDirectories = mutableSetOf<GFile>()

    /**
     * An extractor for the dyld shared cache.
     */
    private val extractor = DSCExtractor(this)

    override fun close() {
        mappedCacheProvider?.close()
        super.close()
    }

    override fun getByteProvider(
        file: GFile,
        monitor: TaskMonitor,
    ): ByteProvider? =
        extractor
            .extractDylibAtAddress(
                fileAddressMap[file] ?: throw IOException("File $file not found in cache!"),
                file.fsrl,
            )

    override fun isValid(monitor: TaskMonitor): Boolean {
        if (!DyldCacheUtils.isDyldCache(provider)) return false
        try {
            val header = DyldCacheHeader(BinaryReader(provider, true))
            return !header.isSubcache // This only works if the user opens the main cache file.
        } catch (_: Exception) {
            return false
        }
    }

    override fun open(monitor: TaskMonitor) {
        mappedCacheProvider =
            MappedDSCByteProvider(
                SplitDyldCache(provider, true, MessageLog(), monitor),
            )
        mappedCacheProvider!!.let { cacheProvider ->
            val splitDyldCache = cacheProvider.splitDyldCache
            for (cacheIndex in 0 until splitDyldCache.size()) {
                splitDyldCache
                    .getDyldCacheHeader(cacheIndex)
                    .mappedImages
                    .forEach { image ->
                        val file = GFileImpl.fromPathString(this, root, image.path, null, false, -1)
                        fileAddressMap[file] = image.address
                        allFilesAndDirectories += generateSequence(file as GFile) { it.parentFile }
                    }
            }
        }
    }

    override fun getListing(directory: GFile?): List<GFile?>? =
        allFilesAndDirectories
            .filter { it.parentFile == (directory ?: root) }
}
