package lol.fairplay.ghidraapple.dyld

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache
import java.io.File
import java.io.IOException
import java.util.TreeMap

/**
 * A [ByteProvider] representing a dyld (shared) cache mapped into virtual memory.
 */
class MappedDSCByteProvider(
    val splitDyldCache: SplitDyldCache,
) : ByteProvider {
    override fun getFile(): File? = null

    val mappingsMap: TreeMap<Long, Pair<Int, DyldCacheMappingInfo>> = TreeMap()
    val maxAddress: Long

    init {
        var maybeMaxAddress = 0L
        for (i in 0 until splitDyldCache.size()) {
            splitDyldCache.getDyldCacheHeader(i).mappingInfos.forEach {
                (it.address + it.size).takeIf { it > maybeMaxAddress }?.let { maybeMaxAddress = it }
                mappingsMap[it.address] = Pair(i, it)
            }
        }
        maxAddress = maybeMaxAddress
    }

    private fun getRelevantCacheIndexAndMapping(index: Long) = mappingsMap.floorEntry(index).value

    override fun getName(): String? = splitDyldCache.getName(0)

    override fun getAbsolutePath() = null

    override fun length() = maxAddress

    @OptIn(ExperimentalStdlibApi::class)
    private fun assertIsValidIndex(index: Long) {
        isValidIndex(index).takeIf { it }
            ?: throw IOException("0x${index.toHexString()} is not a valid address for the mapped cache.")
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun assertIsValidRange(
        index: Long,
        length: Long,
    ) {
        assertIsValidIndex(index)
        getRelevantCacheIndexAndMapping(index)!!
            .takeIf { (_, mapping) -> length <= mapping.size }
            ?: throw IOException(
                "0x${index.toHexString()}-0x${(index + length).toHexString()}" +
                    " is not a valid range for the mapped cache.",
            )
    }

    override fun isValidIndex(index: Long): Boolean {
        val relevantMapping =
            getRelevantCacheIndexAndMapping(index)?.second ?: return false
        return index < relevantMapping.address + relevantMapping.size
    }

    override fun close() {
        this.splitDyldCache.close()
    }

    override fun readByte(index: Long): Byte {
        assertIsValidIndex(index)
        getRelevantCacheIndexAndMapping(index)!!.let { (index, mapping) ->
            return splitDyldCache.getProvider(index).readByte(mapping.fileOffset + (index - mapping.address))
        }
    }

    override fun readBytes(
        index: Long,
        length: Long,
    ): ByteArray {
        assertIsValidRange(index, length)
        getRelevantCacheIndexAndMapping(index)!!.let { (cacheIndex, mapping) ->
            return splitDyldCache
                .getProvider(cacheIndex)
                .readBytes(mapping.fileOffset + (index - mapping.address), length)
        }
    }
}
