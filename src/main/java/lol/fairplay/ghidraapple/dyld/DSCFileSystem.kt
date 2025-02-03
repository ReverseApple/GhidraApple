package lol.fairplay.ghidraapple.dyld

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
import ghidra.program.model.data.StructureDataType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.util.serialization.StructSerializer
import java.io.IOException
import kotlin.collections.plusAssign

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
    companion object {
        val fileByteProviderMap = mutableMapOf<GFile, ByteProvider>()
    }

    /**
     * A map between actual dylib's in the cache and their addresses.
     */
    private val fileAddressMap = mutableMapOf<GFile, Long>()

    /**
     * A set of all files and directories in the cache file system.
     */
    private val allFilesAndDirectories = mutableSetOf<GFile>()

    /**
     * A helper for dealing with the cache.
     */

    var cacheHelper: DSCHelper? = null

    /**
     * The platform the cache is for.
     */
    var platform: Dyld.Platform? = null

    /**
     * The OS version the cache is for.
     */
    var osVersion: Dyld.Version? = null

    /**
     * An extractor for the cache.
     */
    private val extractor = DSCExtractor(this)

    override fun close() {
        cacheHelper?.splitDyldCache?.close()
        super.close()
    }

    override fun getByteProvider(
        file: GFile,
        monitor: TaskMonitor,
    ): ByteProvider? =
        // Ghidra isn't exactly efficient with this method and will call it several times when
        //  opening a file. We cache the result to improve performance. The files shouldn't be
        //  changing at all (why would they?), so this should be safe for us to do here.
        fileByteProviderMap[file]
            ?: extractor
                .extractDylibAtAddress(
                    fileAddressMap[file] ?: throw IOException("File $file not found in cache!"),
                    file.fsrl,
                ).also { fileByteProviderMap[file] = it }

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
        val splitDyldCache = SplitDyldCache(provider, false, MessageLog(), monitor)
        this.cacheHelper = DSCHelper(splitDyldCache)
        for (cacheIndex in 0 until splitDyldCache.size()) {
            splitDyldCache.getDyldCacheHeader(cacheIndex).mappingInfos.forEach {
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
        val headerFileType = splitDyldCache.getDyldCacheHeader(0).toDataType() as StructureDataType
        val headerSerializer =
            StructSerializer(
                headerFileType,
                splitDyldCache.getProvider(0).readBytes(0, headerFileType.length.toLong()),
            )
        this.platform = Dyld.Platform.getPlatform(headerSerializer.getComponentValue("platform"))
        this.osVersion = Dyld.Version(headerSerializer.getComponentValue("osVersion"))
    }

    override fun getListing(directory: GFile?): List<GFile?>? =
        allFilesAndDirectories
            .filter { it.parentFile == (directory ?: root) }
}
