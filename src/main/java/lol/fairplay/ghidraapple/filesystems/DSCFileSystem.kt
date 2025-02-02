package lol.fairplay.ghidraapple.filesystems

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo
import ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon
import ghidra.app.util.bin.format.macho.dyld.DyldFixup
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.DyldCacheUtils
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache
import ghidra.file.formats.ios.ExtractedMacho
import ghidra.file.formats.ios.dyldcache.DyldCacheExtractor
import ghidra.formats.gfilesystem.GFile
import ghidra.formats.gfilesystem.GFileImpl
import ghidra.formats.gfilesystem.GFileSystem
import ghidra.formats.gfilesystem.GFileSystemBase
import ghidra.formats.gfilesystem.annotations.FileSystemInfo
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory
import ghidra.framework.task.GTaskMonitor
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
        fileByteProviderMap[file] ?: DSCExtractor(this, monitor)
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

class DSCHelper(
    val splitDyldCache: SplitDyldCache,
) {
    /**
     * Pointer fixups for the cache.
     */
    val fixupsMap: Map<DyldCacheSlideInfoCommon, List<DyldFixup>> =
        DyldCacheExtractor.getSlideFixups(splitDyldCache, GTaskMonitor())

    fun fixupMemoryRange(
        vmAddress: Long,
        length: Long,
        bytes: ByteArray,
    ): ByteArray =
        bytes.apply {
            for ((slideInfo, fixups) in fixupsMap) {
                fixups.forEach {
                    val fixupAddress = slideInfo.mappingAddress + it.offset
                    // TODO: Determine if we can make this algorithm more efficient.
                    if (fixupAddress < vmAddress || fixupAddress >= vmAddress + length) return@forEach
                    val fixedUpBytes = ExtractedMacho.toBytes(it.value, it.size)
                    val fixupOffsetInRange = (fixupAddress - vmAddress).toInt()
                    fixedUpBytes.copyInto(
                        bytes,
                        fixupOffsetInRange,
                        0,
                        minOf(fixedUpBytes.size, bytes.size - fixupOffsetInRange),
                    )
                }
            }
        }

    /**
     * A map containing virtual memory mapping information.
     */
    val vmMappingsMap =
        TreeMap<Long, Pair<DyldCacheMappingInfo, ByteProvider>>().apply {
            for (cacheIndex in 0 until splitDyldCache.size()) {
                splitDyldCache.getDyldCacheHeader(cacheIndex).mappingInfos.forEach {
                    set(it.address, Pair(it, splitDyldCache.getProvider(cacheIndex)))
                }
            }
        }

    val images =
        splitDyldCache
            .let { splitCache ->
                (0 until splitCache.size()).flatMap { cacheIndex ->
                    splitCache
                        .getDyldCacheHeader(cacheIndex)
                        .mappedImages
                        .map { image -> Pair(image, splitCache.getProvider(cacheIndex)) }
                }
            }

    fun findMachHeaderForImage(path: String): MachHeader? {
        val (matchingImage, byteProviderForCacheFileContainingImage) =
            images
                .firstOrNull { (image) -> image.path == path }
                ?: return null
        val (matchingMapping) =
            findRelevantVMMappingAndCacheByteProvider(matchingImage.address) ?: return null
        return MachHeader(
            byteProviderForCacheFileContainingImage,
            matchingMapping.fileOffset + (matchingImage.address - matchingMapping.address),
        ).parse(splitDyldCache)
    }

    fun findRelevantVMMappingAndCacheByteProvider(vmAddress: Long) =
        vmMappingsMap.floorEntry(vmAddress)?.value?.takeIf { (mapping) ->
            vmAddress < (mapping.address + mapping.size)
        }

    fun isValidVMAddress(vmAddress: Long): Boolean {
        val relevantMapping =
            findRelevantVMMappingAndCacheByteProvider(vmAddress)?.first ?: return false
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
        findRelevantVMMappingAndCacheByteProvider(vmAddress)!!
            .takeIf { (mapping) ->
                length <= mapping.size - (vmAddress - mapping.address)
            }
            ?: throw IOException(
                "0x${vmAddress.toHexString()}-0x${(vmAddress + length).toHexString()}" +
                    " is not a valid range for the mapped cache.",
            )
    }

    fun readMappedBytes(
        vmAddress: Long,
        length: Long,
        fixedUp: Boolean = true,
    ): ByteArray {
        assertIsValidVMRange(vmAddress, length)
        findRelevantVMMappingAndCacheByteProvider(vmAddress)!!
            .let { (mapping, provider) ->
                return provider
                    .readBytes(
                        mapping.fileOffset + (vmAddress - mapping.address),
                        length,
                    ).let { if (fixedUp) fixupMemoryRange(vmAddress, length, it) else it }
            }
    }

    fun readMappedCString(vmAddress: Long): String? =
        findRelevantVMMappingAndCacheByteProvider(vmAddress)
            ?.let { (mapping, provider) ->
                var string = ""
                var currentOffset = mapping.fileOffset + (vmAddress - mapping.address)
                string_builder@ do {
                    val byte = provider.readByte(currentOffset)
                    if (byte == 0x00.toByte()) break@string_builder
                    string += byte.toInt().toChar()
                    currentOffset++
                } while // Don't keep reading outside mapped sections.
                (currentOffset <= (mapping.fileOffset + mapping.size))
                string.takeIf { it != "" }
            }
}
