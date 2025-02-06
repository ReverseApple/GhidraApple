package lol.fairplay.ghidraapple.dyld

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo
import ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon
import ghidra.app.util.bin.format.macho.dyld.DyldFixup
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache
import ghidra.file.formats.ios.ExtractedMacho
import ghidra.file.formats.ios.dyldcache.DyldCacheExtractor
import ghidra.framework.task.GTaskMonitor
import ghidra.program.model.data.StructureDataType
import lol.fairplay.ghidraapple.util.serialization.StructSerializer
import java.io.IOException
import java.util.TreeMap
import kotlin.collections.forEach
import kotlin.collections.set

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

    /**
     * Whether the cache has stub optimizations instead of simply using the in-dylib stubs.
     *
     * [The stub optimizations are only included in universal-typed caches](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache_builder/NewSharedCacheBuilder.cpp#L2747),
     * [which are marked in the `cacheType` field](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache_builder/SubCache.cpp#L1526)
     * [by the value `kDyldSharedCacheTypeUniversal`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache_builder/SubCache.cpp#L1348)
     * ([which is equal to `2`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache-builder/dyld_cache_format.h#L622)).
     *
     */
    val cacheHasStubOptimizations: Boolean =
        {
            val headerDataType = splitDyldCache.getDyldCacheHeader(0).toDataType() as StructureDataType
            val cacheType: Long =
                StructSerializer(
                    headerDataType,
                    splitDyldCache.getProvider(0).readBytes(0, headerDataType.length.toLong()),
                ).getComponentValue("cacheType")
            cacheType == 2L
        }()

    /**
     * The virtual memory mappings that include stubs.
     *
     * [Stub mappings are flagged with `DYLD_CACHE_MAPPING_TEXT_STUBS`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache_builder/SubCache.cpp#L1390),
     * [which is equal to `1 << 3`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache-builder/dyld_cache_format.h#L131).
     */
    val stubOptimizationMappings =
        (0 until splitDyldCache.size())
            .fold(listOf<Pair<DyldCacheMappingAndSlideInfo, ByteProvider>>()) { acc, cacheIndex ->
                val mappings =
                    splitDyldCache
                        .getDyldCacheHeader(cacheIndex)
                        .cacheMappingAndSlideInfos
                        .filter { it.flags and (1 shl 3) != 0L }
                var mappingPairs =
                    mutableListOf<Pair<DyldCacheMappingAndSlideInfo, ByteProvider>>()
                mappings.forEach {
                    val (_, mappingProvider) =
                        findRelevantVMMappingAndCacheByteProvider(it.address) ?: return@forEach
                    mappingPairs += Pair(it, mappingProvider)
                }
                return@fold acc + mappingPairs
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
