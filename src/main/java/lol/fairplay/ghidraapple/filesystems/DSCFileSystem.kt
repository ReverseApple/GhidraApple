package lol.fairplay.ghidraapple.filesystems

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo
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
import lol.fairplay.ghidraapple.core.objc.modelling.Dyld
import lol.fairplay.ghidraapple.core.serialization.StructSerializer
import lol.fairplay.ghidraapple.dyld.DSCExtractor
import java.io.IOException
import java.util.TreeMap

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
     * A map between actual dylib's in the cache and their addresses.
     */
    private val fileAddressMap = mutableMapOf<GFile, Long>()

    /**
     * A set of all files and directories in the cache file system.
     */
    private val allFilesAndDirectories = mutableSetOf<GFile>()

    /**
     * A helper for dealing with memory addresses in the cache.
     */

    var memoryHelper: DSCMemoryHelper? = null

    /**
     * The platform the cache is for.
     */
    var platform: Dyld.Platform? = null

    /**
     * The OS version the cache is for.
     */
    var osVersion: Dyld.Version? = null

    override fun close() {
        memoryHelper?.splitDyldCache?.close()
        super.close()
    }

    override fun getByteProvider(
        file: GFile,
        monitor: TaskMonitor,
    ): ByteProvider? =
        DSCExtractor(this, monitor)
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
        val splitDyldCache = SplitDyldCache(provider, false, MessageLog(), monitor)
        this.memoryHelper = DSCMemoryHelper(splitDyldCache)
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

class DSCMemoryHelper(
    val splitDyldCache: SplitDyldCache,
) {
    /**
     * A map containing virtual memory mapping information.
     */
    val vmMappingsMap: TreeMap<Long, Pair<Int, DyldCacheMappingInfo>> = TreeMap()

    init {
        for (cacheIndex in 0 until splitDyldCache.size()) {
            splitDyldCache.getDyldCacheHeader(cacheIndex).mappingInfos.forEach {
                vmMappingsMap[it.address] = Pair(cacheIndex, it)
            }
        }
    }

    fun getRelevantCacheIndexAndVMMapping(vmAddress: Long) =
        vmMappingsMap.floorEntry(vmAddress)?.value?.takeIf { (_, mapping) ->
            vmAddress < (mapping.address + mapping.size)
        }

    fun isValidVMAddress(vmAddress: Long): Boolean {
        val relevantMapping =
            getRelevantCacheIndexAndVMMapping(vmAddress)?.second ?: return false
        return vmAddress < relevantMapping.address + relevantMapping.size
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun assertIsValidVMAddress(vmAddress: Long) {
        isValidVMAddress(vmAddress).takeIf { it }
            ?: throw IOException("0x${vmAddress.toHexString()} is not a valid address for the mapped cache.")
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun assertIsValidVMRange(
        vmAddress: Long,
        length: Long,
    ) {
        assertIsValidVMAddress(vmAddress)
        getRelevantCacheIndexAndVMMapping(vmAddress)!!
            .takeIf { (_, mapping) ->
                length <= mapping.size - (vmAddress - mapping.address)
            }
            ?: throw IOException(
                "0x${vmAddress.toHexString()}-0x${(vmAddress + length).toHexString()}" +
                    " is not a valid range for the mapped cache.",
            )
    }

    fun readMappedByte(vmAddress: Long): Byte {
        assertIsValidVMAddress(vmAddress)
        getRelevantCacheIndexAndVMMapping(vmAddress)!!.let { (cacheIndex, mapping) ->
            return splitDyldCache.getProvider(cacheIndex).readByte(mapping.fileOffset + (vmAddress - mapping.address))
        }
    }

    fun readMappedBytes(
        vmAddress: Long,
        length: Long,
    ): ByteArray {
        assertIsValidVMRange(vmAddress, length)
        getRelevantCacheIndexAndVMMapping(vmAddress)!!.let { (cacheIndex, mapping) ->
            return splitDyldCache
                .getProvider(cacheIndex)
                .readBytes(mapping.fileOffset + (vmAddress - mapping.address), length)
        }
    }

    fun readMappedCString(vmAddress: Long): String? =
        getRelevantCacheIndexAndVMMapping(vmAddress)
            ?.let { (cacheIndex, mapping) ->
                var string = ""
                var currentOffset = mapping.fileOffset + (vmAddress - mapping.address)
                string_builder@ do {
                    val byte = this.splitDyldCache.getProvider(cacheIndex).readByte(currentOffset)
                    if (byte == 0x00.toByte()) break@string_builder
                    string += byte.toInt().toChar()
                    currentOffset++
                } while // Don't keep reading outside mapped sections.
                (currentOffset <= (mapping.fileOffset + mapping.size))
                string.takeIf { it != "" }
            }
}
