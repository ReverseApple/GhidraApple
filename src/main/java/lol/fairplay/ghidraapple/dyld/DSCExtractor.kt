package lol.fairplay.ghidraapple.dyld

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.app.util.bin.format.macho.MachHeaderFlags
import ghidra.app.util.bin.format.macho.Section
import ghidra.app.util.bin.format.macho.commands.DataInCodeCommand
import ghidra.app.util.bin.format.macho.commands.DyldExportsTrieCommand
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommand
import ghidra.app.util.bin.format.macho.commands.DynamicLinkerCommand
import ghidra.app.util.bin.format.macho.commands.DynamicSymbolTableCommand
import ghidra.app.util.bin.format.macho.commands.ExportTrie
import ghidra.app.util.bin.format.macho.commands.FunctionStartsCommand
import ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand
import ghidra.app.util.bin.format.macho.commands.LoadCommand
import ghidra.app.util.bin.format.macho.commands.LoadCommandTypes
import ghidra.app.util.bin.format.macho.commands.NList
import ghidra.app.util.bin.format.macho.commands.SegmentCommand
import ghidra.app.util.bin.format.macho.commands.SymbolTableCommand
import ghidra.formats.gfilesystem.FSRL
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.collections.plus

/**
 * The dyld project includes a library called `dsc_extractor`. The logic in this file is largely copied from
 * that library. The logic is copied as `dsc_extractor` is not portable to non-Apple platforms.
 */

class DSCExtractor(
    private val dscFileSystem: DSCFileSystem,
    // 100 MiB default
    private val maxDylibSize: Int = 100 * (1024 * 1024),
) {
    fun extractDylibAtAddress(
        startAddress: Long,
        fsrl: FSRL,
    ): ByteProvider {
        // TODO: See if we can utilize an automatically-resizing data structure for the buffer(s).

        val newDylibBuffer: ByteBuffer = ByteBuffer.allocate(maxDylibSize).order(ByteOrder.LITTLE_ENDIAN)

        val dscMemoryHelper = dscFileSystem.cacheHelper!!

        val (inCacheMachHeader, cacheFileByteProvider) =
            dscMemoryHelper
                .findRelevantVMMappingAndCacheByteProvider(startAddress)!!
                .let { (mappingInfo, provider) ->
                    val fileOffsetOfDylib = mappingInfo.fileOffset + (startAddress - mappingInfo.address)
                    Pair(
                        MachHeader(provider, fileOffsetOfDylib).parse(dscMemoryHelper.splitDyldCache),
                        provider,
                    )
                }

        var textOffsetInCache = 0L

        for (segment in inCacheMachHeader.allSegments) {
            if (segment.segmentName == "__TEXT") {
                textOffsetInCache =
                    segment.vMaddress -
                    dscMemoryHelper.splitDyldCache
                        .getDyldCacheHeader(0)
                        .unslidLoadAddress()
            }
            if (segment.segmentName == "__LINKEDIT") continue
            val segmentBytes = dscMemoryHelper.readMappedBytes(segment.vMaddress, segment.vMsize)
            newDylibBuffer.put(segmentBytes)
        }

        val linkeditOptimizer =
            LinkeditOptimizer(
                dscMemoryHelper,
                newDylibBuffer,
            )

        // Fix up and optimize the load commands.
        linkeditOptimizer.optimizeLoadCommands()

        // Create a new `__LINKEDIT` segment.
        val offsetForNewLinkeditSegment = newDylibBuffer.position()
        val bufferForNewLinkeditSegment = ByteBuffer.allocate(1 shl 20)
        linkeditOptimizer.optimizeLinkedit(inCacheMachHeader, bufferForNewLinkeditSegment, textOffsetInCache)

        // Write the new `__LINKEDIT` segment.
        newDylibBuffer
            .position(offsetForNewLinkeditSegment)
            .put(bufferForNewLinkeditSegment.array())

        // Get the written bytes and return them wrapped in a provider.
        val endPosition = newDylibBuffer.position()
        val finalBytes = ByteArray(endPosition)
        newDylibBuffer.get(0, finalBytes)
        return ByteArrayProvider(finalBytes, fsrl)
    }
}

class LinkeditOptimizer(
    val dscHelper: DSCHelper,
    val newDyibBuffer: ByteBuffer,
) {
    private var linkeditSegmentCommand: SegmentCommand? = null
    private var linkeditBaseAddressInCache: Long = 0L
    var exportsTrie: ExportTrie? = null

    var symbolTableCommand: SymbolTableCommand? = null
    var dynamicSymbolTableCommand: DynamicSymbolTableCommand? = null
    var functionStartsCommand: FunctionStartsCommand? = null
    var dataInCodeCommand: DataInCodeCommand? = null

    var reexportedDependencies = setOf<Int>()

    fun fixupSegmentCommand(
        oldSegmentCommand: SegmentCommand,
        machHeader: MachHeader,
        name: String? = null,
        vmAddr: Long? = null,
        vmSize: Long? = null,
        fileOffset: Long? = null,
        fileSize: Long? = null,
        maxProt: Int? = null,
        initProt: Int? = null,
        numSections: Int? = null,
        flags: Int? = null,
        forEachSectionAndStartIndex: (Section, Int) -> Unit = { _, _ -> },
    ) {
        val readerForNewDylib = BinaryReader(ByteArrayProvider(newDyibBuffer.array()), true)
        readerForNewDylib.pointerIndex = oldSegmentCommand.startIndex
        val newCommandBytes =
            SegmentCommand.create(
                machHeader.magic,
                name ?: oldSegmentCommand.segmentName,
                vmAddr ?: oldSegmentCommand.vMaddress,
                vmSize ?: oldSegmentCommand.vMsize,
                fileOffset ?: oldSegmentCommand.fileOffset,
                fileSize ?: oldSegmentCommand.fileOffset,
                maxProt ?: oldSegmentCommand.maxProtection,
                initProt ?: oldSegmentCommand.initProtection,
                numSections ?: oldSegmentCommand.numberOfSections,
                flags ?: oldSegmentCommand.flags,
            )
        // The [SegmentCommand.create] method does not include the correct command size if the segment
        //  has sections (which they basically all do), so we need to copy the original size back into
        //  the bytes before writing them to the new dylib buffer.
        ByteBuffer
            .allocate(Int.SIZE_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(oldSegmentCommand.commandSize)
            .array()
            .copyInto(newCommandBytes, Int.SIZE_BYTES * 1)

        // Write the new command bytes into the buffer.
        newDyibBuffer.put(oldSegmentCommand.startIndex.toInt(), newCommandBytes)

        oldSegmentCommand.sections.forEachIndexed { index, section ->
            forEachSectionAndStartIndex(
                section,
                (
                    oldSegmentCommand.startIndex +
                        newCommandBytes.size +
                        (section.toDataType().length * index)
                ).toInt(),
            )
        }
    }

    fun optimizeLoadCommands() {
        val indexOfFlags = Int.SIZE_BYTES * 6
        val oldFlags = newDyibBuffer.getInt(indexOfFlags)
        newDyibBuffer.putInt(indexOfFlags, oldFlags and MachHeaderFlags.MH_DYLIB_IN_CACHE.inv())

        var cumulativeFileSize = 0L
        var depIndex = 0

        val machHeader =
            MachHeader(
                ByteArrayProvider(newDyibBuffer.array()),
            ).parse(dscHelper.splitDyldCache)

        for (command in machHeader.loadCommands) {
            when (command) {
                is SegmentCommand -> {
                    if (command.segmentName == "__LINKEDIT") {
                        linkeditSegmentCommand = command
                        linkeditBaseAddressInCache = command.vMaddress
                        linkeditBaseAddressInCache -= command.fileOffset
                    }

                    fixupSegmentCommand(
                        command,
                        machHeader,
                        fileOffset = cumulativeFileSize,
                        fileSize = command.vMsize,
                    ) { section, startIndex ->
                        if (section.offset != 0) {
                            newDyibBuffer
                                .putInt(
                                    startIndex.toInt() +
                                        // skip names
                                        (16 * 2) +
                                        // skip address and size
                                        (if (machHeader.is32bit) 4 else 8) * 2,
                                    (cumulativeFileSize + (section.address - command.vMaddress)).toInt(),
                                )
                        }
                    }

                    cumulativeFileSize += command.fileSize
                }
                is DyldInfoCommand -> {
                    fun DyldInfoCommand.serializeForExtractor(): ByteArray {
                        val buffer =
                            ByteBuffer
                                .allocate(this.commandSize)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .putInt(command.commandType)
                                .putInt(command.commandSize)
                                // rebase offset and size
                                .putInt(0)
                                .putInt(0)
                                // bind offset and size
                                .putInt(0)
                                .putInt(0)
                                // weak bind offset and size
                                .putInt(0)
                                .putInt(0)
                                // lazy bind offset and size
                                .putInt(0)
                                .putInt(0)
                                // export offset and size
                                .putInt(0)
                                .putInt(0)
                        return buffer.array()
                    }
                    exportsTrie = command.exportTrie
                    newDyibBuffer.put(command.startIndex.toInt(), command.serializeForExtractor())
                }
                is DyldExportsTrieCommand -> {
                    fun DyldExportsTrieCommand.serializeForExtractor(): ByteArray {
                        val buffer =
                            ByteBuffer
                                .allocate(this.commandSize)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .putInt(command.commandType)
                                .putInt(command.commandSize)
                                // data offset and size
                                .putInt(0)
                                .putInt(0)
                        return buffer.array()
                    }
                    exportsTrie = command.exportTrie
                    newDyibBuffer.put(command.startIndex.toInt(), command.serializeForExtractor())
                }
                is SymbolTableCommand -> this.symbolTableCommand = command
                is DynamicSymbolTableCommand -> this.dynamicSymbolTableCommand = command
                is FunctionStartsCommand -> this.functionStartsCommand = command
                is DataInCodeCommand -> this.dataInCodeCommand = command
                is DynamicLinkerCommand -> {
                    val handledLinkCommands =
                        arrayOf(
                            LoadCommandTypes.LC_LOAD_DYLIB,
                            LoadCommandTypes.LC_LOAD_WEAK_DYLIB,
                            LoadCommandTypes.LC_REEXPORT_DYLIB,
                            LoadCommandTypes.LC_LOAD_UPWARD_DYLIB,
                            // Some link-ish load commands aren't handled, but we are copying this logic from
                            //  `dsc_extractor`, so I guess we have to trust it.
                        )
                    if (command.commandType !in handledLinkCommands) continue
                    depIndex++
                    if (command.commandType == LoadCommandTypes.LC_REEXPORT_DYLIB) reexportedDependencies += depIndex
                }
                is LinkEditDataCommand -> {
                    if (command.commandType == LoadCommandTypes.LC_SEGMENT_SPLIT_INFO) {
                        // TODO: Fix this.
                        // `dsc_extractor` removes this command when encountering it. I haven't figured out how to
                        //  cleanly remove load  commands at the moment, so we'll just throw. Thankfully, it seems
                        //  that the only time we'll encounter this is on iOS 9 caches.
                        throw IOException("Unexpected `LC_SEGMENT_SPLIT_INFO` command.")
                    }
                }
            }
        }
    }

    fun optimizeLinkedit(
        machHeader: MachHeader,
        newLinkeditSegmentBuffer: ByteBuffer,
        textOffsetInCache: Long,
        // TODO: Handle `localSymbolsCache`
    ) {
        // Copy the segment commands into new values to stop the compiler from complaining when we use them later.
        var newLinkeditSegmentCommand =
            linkeditSegmentCommand?.let {
                val readerForNewDylib = BinaryReader(ByteArrayProvider(newDyibBuffer.array()), true)
                readerForNewDylib.pointerIndex = it.startIndex
                val newSegmentCommand = SegmentCommand(readerForNewDylib, machHeader.is32bit)
                return@let newSegmentCommand
            } ?: return
        val symbolTableCommandCopy =
            symbolTableCommand ?: return
        val dynamicSymbolTableCommandCopy =
            dynamicSymbolTableCommand ?: return

        // Load commands may include a file-offset to specific data. Because it is a file offset, we'll need
        //  to make sure we're looking in the correct file. In most (if not all) cases, that will be the one
        //  that is mapped to where the `__LINKEDIT` segment lives (or simply, the one that contains it). It
        //  is currently unknown if there are any cases where the "linker data" will be elsewhere, but there
        //  shouldn't be. For now, it should be a good assumption that it will be in `__LINKEDIT`.
        val (_, providerContainingLinkeditSegment) =
            dscHelper.findRelevantVMMappingAndCacheByteProvider(
                // We never changed the VM address, so we can use it to find the relevant provider.
                newLinkeditSegmentCommand.vMaddress,
            )!!

        fun <T : LoadCommand> writeDataToLinkedit(
            command: T,
            pointerAlignAfter: Boolean = true,
            preWriteCommandFixup: (T) -> Unit,
        ) {
            preWriteCommandFixup(command)
            val bytesToWrite =
                providerContainingLinkeditSegment.readBytes(
                    command.linkerDataOffset.toLong(),
                    command.linkerDataSize.toLong(),
                )
            newLinkeditSegmentBuffer.put(bytesToWrite)
            if (pointerAlignAfter) {
                val pointerSize = if (machHeader.is32bit) 4 else 8
                while (
                    (
                        (
                            newLinkeditSegmentCommand.fileOffset +
                                newLinkeditSegmentBuffer.position()
                        ) % pointerSize
                    ).toInt() != 0
                ) {
                    newLinkeditSegmentBuffer.put(0x00)
                }
            }
        }

        fun writeLinkeditCommandData(
            command: LinkEditDataCommand,
            pointerAlignAfter: Boolean = true,
        ) {
            writeDataToLinkedit(command, pointerAlignAfter) {
                val offsetForLinkeditCommandData = newLinkeditSegmentBuffer.position()
                newDyibBuffer
                    .position(it.startIndex.toInt())
                    .putInt(it.commandType)
                    .putInt(it.commandSize)
                    .putInt(newLinkeditSegmentCommand.fileOffset.toInt() + offsetForLinkeditCommandData)
                    .putInt(it.linkerDataSize)
            }
        }

        // These two are first and second in the new `__LINKEDIT` section.

        functionStartsCommand?.let { writeLinkeditCommandData(it) }
        dataInCodeCommand?.let { writeLinkeditCommandData(it) }

        // Now it's onto the tricky part: rebuilding the symbol table.

        // TODO: Maybe clean up this logic if and when Ghidra fixes their symbol table parsing.

        val (symbolsFileOffset, stringsFileOffset) =
            symbolTableCommandCopy.let {
                // Ghidra's parsing may sometimes parse these offsets as signed integers and return negative
                //  values. This obviously doesn't make sense for file offsets, so they need to be converted
                //  into unsigned integers to access their proper values.
                Pair(
                    it.symbolOffset.toUInt(),
                    it.stringTableOffset.toUInt(),
                )
            }

        // Start reading from the symbol table as it exists in the cache file.

//        val providerContainingSymbolTable = dscHelper.findRelevantVMMappingAndCacheByteProvider()
        val readerForSymbolTable = BinaryReader(providerContainingLinkeditSegment, true)
        readerForSymbolTable.pointerIndex = symbolsFileOffset.toLong()

        // Read the first entry. We do this to use it later to calculate the size of our new symbol table.

        val firstNList = NList(readerForSymbolTable, machHeader.is32bit)

        // TODO: Handle any additional symbols that should be added.

        val newSymbolCount = symbolTableCommandCopy.numberOfSymbols
        val newSymbolTableBuffer =
            ByteBuffer
                // We assume all NList entries are the same size (which they should be).
                .allocate(newSymbolCount * firstNList.toDataType().length)
                .order(ByteOrder.LITTLE_ENDIAN)

        var symbolTableStringPool = "\u0000" // Per `dsc_extractor`: the first entry is always an empty string.

        repeat(symbolTableCommandCopy.numberOfSymbols - 1) {
            val nList = NList(readerForSymbolTable, machHeader.is32bit)
            nList.initString(readerForSymbolTable, stringsFileOffset.toLong())
            newSymbolTableBuffer
                .putInt(symbolTableStringPool.length) // String offset where we'll write the string (below).
                .put(nList.type)
                .put(nList.section)
                .putShort(nList.description)
                .apply {
                    if (nList.is32bit) putInt(nList.value.toInt()) else putLong(nList.value)
                }
            // It's important that this happens *after* we write the entry so the string offset is correct.
            symbolTableStringPool += nList.string + "\u0000"
        }

        // We need to pointer-align the string pool size.
        val pointerSize = if (machHeader.is32bit) 4 else 8
        while (symbolTableStringPool.length % pointerSize != 0) symbolTableStringPool += "\u0000"

        // Now it's time to write the stuff.

        val fileOffsetForNewSymbols =
            newLinkeditSegmentCommand.fileOffset + newLinkeditSegmentBuffer.position()

        newLinkeditSegmentBuffer.put(newSymbolTableBuffer.array())

        val fileOffsetForIndirectSymbols =
            newLinkeditSegmentCommand.fileOffset + newLinkeditSegmentBuffer.position()

        writeDataToLinkedit(dynamicSymbolTableCommandCopy) {
            newDyibBuffer
                .position(it.startIndex.toInt())
                .putInt(it.commandType)
                .putInt(it.commandSize)
                .putInt(it.localSymbolIndex)
                .putInt(it.localSymbolCount)
                .putInt(it.externalSymbolIndex)
                .putInt(it.externalSymbolCount)
                .putInt(it.undefinedSymbolIndex)
                .putInt(it.undefinedSymbolIndex)
                .putInt(it.tableOfContentsOffset)
                .putInt(it.tableOfContentsSize)
                .putInt(it.moduleTableOffset)
                .putInt(it.moduleTableSize)
                .putInt(it.referencedSymbolTableOffset)
                .putInt(it.referencedSymbolTableSize)
                .putInt(fileOffsetForIndirectSymbols.toInt())
                .putInt(it.indirectSymbolTableSize)
                .putInt(0)
                .putInt(0)
                .putInt(0)
                .putInt(0)
        }

        val fileOffsetForStringPool =
            newLinkeditSegmentCommand.fileOffset + newLinkeditSegmentBuffer.position()

        newLinkeditSegmentBuffer.put(symbolTableStringPool.toByteArray())

        newDyibBuffer
            .position(symbolTableCommandCopy.startIndex.toInt())
            .putInt(symbolTableCommandCopy.commandType)
            .putInt(symbolTableCommandCopy.commandSize)
            .putInt(fileOffsetForNewSymbols.toInt())
            .putInt(newSymbolCount)
            .putInt(fileOffsetForStringPool.toInt())
            .putInt(symbolTableStringPool.length)

        // This is not the calculation that `dsc_extractor` does, but it's easier on us to do it this way.
        val newLinkEditFileSize = newLinkeditSegmentBuffer.position()

        // Finally, we fix up the original `__LINKEDIT` segment command.
        fixupSegmentCommand(
            newLinkeditSegmentCommand,
            machHeader,
            fileSize = newLinkeditSegmentBuffer.position().toLong(),
            vmSize = ((newLinkEditFileSize + 4095) and (4096).inv()).toLong(),
        )
    }
}
