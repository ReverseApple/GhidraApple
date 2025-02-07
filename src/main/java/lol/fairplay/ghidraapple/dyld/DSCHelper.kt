package lol.fairplay.ghidraapple.dyld

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo
import ghidra.app.util.bin.format.macho.dyld.DyldCacheSlideInfoCommon
import ghidra.app.util.bin.format.macho.dyld.DyldFixup
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache
import ghidra.file.formats.ios.ExtractedMacho
import ghidra.file.formats.ios.dyldcache.DyldCacheExtractor
import ghidra.framework.task.GTaskMonitor
import ghidra.program.model.data.StructureDataType
import lol.fairplay.ghidraapple.util.serialization.StructSerializer
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.TreeMap
import kotlin.collections.forEach
import kotlin.collections.set
import kotlin.reflect.cast

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
     * A list of all mappings in the cache, along with the byte providers for their
     *  containing files and the file indexes of their containing files.
     */
    val allMappings =
        (0 until splitDyldCache.size())
            .fold(
                listOf<Triple<DyldCacheMappingAndSlideInfo, ByteProvider, Int>>(),
            ) { list, cacheIndex ->
                list +
                    splitDyldCache
                        .getDyldCacheHeader(cacheIndex)
                        .cacheMappingAndSlideInfos
                        .map { Triple(it, splitDyldCache.getProvider(cacheIndex), cacheIndex) }
            }

    /**
     * A map containing virtual memory mapping information.
     */
    val vmMappingsMap =
        TreeMap<Long, Triple<DyldCacheMappingAndSlideInfo, ByteProvider, Int>>().apply {
            allMappings.forEach {
                set(it.first.address, it)
            }
        }

    fun findRelevantMapping(vmAddress: Long) =
        vmMappingsMap.floorEntry(vmAddress)?.value?.takeIf { (mapping) ->
            vmAddress < (mapping.address + mapping.size)
        }

    fun isValidVMAddress(vmAddress: Long): Boolean {
        val (relevantMapping) =
            findRelevantMapping(vmAddress) ?: return false
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
        findRelevantMapping(vmAddress)!!
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
        findRelevantMapping(vmAddress)!!
            .let { (mapping, provider) ->
                return provider
                    .readBytes(
                        mapping.fileOffset + (vmAddress - mapping.address),
                        length,
                    ).let { if (fixedUp) fixupMemoryRange(vmAddress, length, it) else it }
            }
    }

    fun byteBufferOfMappedBytes(
        vmAddress: Long,
        length: Long,
        byteOrder: ByteOrder,
    ): ByteBuffer =
        ByteBuffer
            .wrap(readMappedBytes(vmAddress, length))
            .order(byteOrder)

    inline fun <reified T : Number> readMappedNumber(
        vmAddress: Long,
        byteOrder: ByteOrder = ByteOrder.LITTLE_ENDIAN,
    ): T =
        T::class.cast(
            when (T::class) {
                Long::class -> byteBufferOfMappedBytes(vmAddress, 8, byteOrder).long
                ULong::class -> byteBufferOfMappedBytes(vmAddress, 8, byteOrder).long.toULong()
                Int::class -> byteBufferOfMappedBytes(vmAddress, 4, byteOrder).int
                UInt::class -> byteBufferOfMappedBytes(vmAddress, 4, byteOrder).int.toUInt()
                Short::class -> byteBufferOfMappedBytes(vmAddress, 2, byteOrder).short
                UShort::class -> byteBufferOfMappedBytes(vmAddress, 2, byteOrder).short.toUShort()
                Float::class -> byteBufferOfMappedBytes(vmAddress, 4, byteOrder).float
                Double::class -> byteBufferOfMappedBytes(vmAddress, 8, byteOrder).double
                else -> throw IllegalArgumentException("Unsupported type: ${T::class.simpleName}")
            },
        )

    fun readMappedCString(vmAddress: Long): String? =
        findRelevantMapping(vmAddress)
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

    val images get() =
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
            findRelevantMapping(matchingImage.address) ?: return null
        return MachHeader(
            byteProviderForCacheFileContainingImage,
            matchingMapping.fileOffset + (matchingImage.address - matchingMapping.address),
        ).parse(splitDyldCache)
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
    val cacheHasStubOptimizations: Boolean
        get() {
            val headerDataType = splitDyldCache.getDyldCacheHeader(0).toDataType() as StructureDataType
            val cacheType: Long =
                StructSerializer(
                    headerDataType,
                    splitDyldCache.getProvider(0).readBytes(0, headerDataType.length.toLong()),
                ).getComponentValue("cacheType")
            return cacheType == 2L
        }

    /**
     * The virtual memory mappings that include stubs.
     *
     * [Stub mappings are flagged with `DYLD_CACHE_MAPPING_TEXT_STUBS`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache_builder/SubCache.cpp#L1390),
     * [which is equal to `1 << 3`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache-builder/dyld_cache_format.h#L131).
     */
    val stubOptimizationMappings get() =
        allMappings.filter { (mapping) -> mapping.flags and (1 shl 3) != 0L }

    /**
     * The virtual memory mappings that include stubs.
     *
     * [Read-only mappings are flagged with `DYLD_CACHE_READ_ONLY_DATA`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache_builder/SubCache.cpp#L1449),
     * [which is equal to `1 << 5`](
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1235.2/cache-builder/dyld_cache_format.h#L133).
     *
     * Note: This was only added in more recent versions of `dyld`.
     */
    val readOnlyMappings get() =
        allMappings.filter { (mapping) -> mapping.flags and (1 shl 5) != 0L }
}
