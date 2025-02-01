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
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommandConstants
import ghidra.app.util.bin.format.macho.commands.DynamicLinkerCommand
import ghidra.app.util.bin.format.macho.commands.DynamicSymbolTableCommand
import ghidra.app.util.bin.format.macho.commands.ExportTrie
import ghidra.app.util.bin.format.macho.commands.FunctionStartsCommand
import ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand
import ghidra.app.util.bin.format.macho.commands.LoadCommand
import ghidra.app.util.bin.format.macho.commands.LoadCommandFactory
import ghidra.app.util.bin.format.macho.commands.LoadCommandTypes
import ghidra.app.util.bin.format.macho.commands.NList
import ghidra.app.util.bin.format.macho.commands.SegmentCommand
import ghidra.app.util.bin.format.macho.commands.SymbolTableCommand
import ghidra.formats.gfilesystem.FSRL
import lol.fairplay.ghidraapple.filesystems.DSCFileSystem
import lol.fairplay.ghidraapple.filesystems.DSCMemoryHelper
import lol.fairplay.ghidraapple.filesystems.GADyldCacheFileSystem
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
    private val maxDylibSize: Int = 1024 * 1024 * 100,
) {
    @OptIn(ExperimentalStdlibApi::class)
    fun extractDylibAtAddress(
        startAddress: Long,
        fsrl: FSRL,
    ): ByteProvider {
        // TODO: See if we can utilize an automatically-resizing data structure for the buffer(s).

        val bufferForExtractedDylib: ByteBuffer = ByteBuffer.allocate(maxDylibSize).order(ByteOrder.LITTLE_ENDIAN)

        val dscMemoryHelper = dscFileSystem.memoryHelper!!

        val (machHeader, cacheFileByteProvider) =
            dscMemoryHelper
                .getRelevantCacheIndexAndVMMapping(startAddress)!!
                .let { (cacheIndex, mappingInfo) ->
                    val fileOffsetOfDylib = mappingInfo.fileOffset + (startAddress - mappingInfo.address)
                    Pair(
                        MachHeader(
                            dscMemoryHelper.splitDyldCache.getProvider(cacheIndex),
                            fileOffsetOfDylib,
                        ).parse(dscMemoryHelper.splitDyldCache),
                        dscMemoryHelper.splitDyldCache.getProvider(cacheIndex),
                    )
                }

//        val machHeader =
//            MachHeader(mappedCacheProvider, startAddress)
//                .parse(mappedCacheProvider.splitDyldCache)

        var textOffsetInCache = 0L

        for (segment in machHeader.allSegments) {
            if (segment.segmentName == "__TEXT") {
                textOffsetInCache =
                    segment.vMaddress -
                    dscMemoryHelper.splitDyldCache
                        .getDyldCacheHeader(0)
                        .unslidLoadAddress()
            }
            if (segment.segmentName == "__LINKEDIT") continue
            val segmentBytes = dscMemoryHelper.readMappedBytes(segment.vMaddress, segment.vMsize)
            bufferForExtractedDylib.put(segmentBytes)
        }
        val offsetForNewLinkeditSegment = bufferForExtractedDylib.position()

        val bufferForNewLinkeditSegment = ByteBuffer.allocate(1 shl 20)

        val linkeditOptimizer =
            LinkeditOptimizerNew(
                cacheFileByteProvider,
                dscMemoryHelper,
                bufferForExtractedDylib,
            )

        linkeditOptimizer.optimizeLoadCommands()
        linkeditOptimizer.optimizeLinkedit(machHeader, bufferForNewLinkeditSegment, textOffsetInCache)

        bufferForExtractedDylib
            .position(offsetForNewLinkeditSegment)
            .put(bufferForNewLinkeditSegment.array())

        val finalBytes = ByteArray(bufferForExtractedDylib.position())
        bufferForExtractedDylib.get(0, finalBytes)
        return ByteArrayProvider(finalBytes, fsrl)
    }
}

class LinkeditOptimizerNew(
    // TODO: We gotta pick a better name for this.
    val byteProviderForCacheFileContainingDylib: ByteProvider,
    val dscMemoryHelper: DSCMemoryHelper,
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
        commandStartIndex: Long,
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
    ) {
        val readerForNewDylib = BinaryReader(ByteArrayProvider(newDyibBuffer.array()), true)
        readerForNewDylib.pointerIndex = commandStartIndex
        val oldSegmentCommand = SegmentCommand(readerForNewDylib, machHeader.is32bit)
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
            ).parse(dscMemoryHelper.splitDyldCache)

        for (command in machHeader.loadCommands) {
            when (command) {
                is SegmentCommand -> {
                    if (command.segmentName == "__LINKEDIT") {
                        linkeditSegmentCommand = command
                        linkeditBaseAddressInCache = command.vMaddress
                        linkeditBaseAddressInCache -= command.fileOffset
                    }

                    fixupSegmentCommand(
                        command.startIndex,
                        machHeader,
                        fileOffset = cumulativeFileSize,
                        fileSize = command.vMsize,
                    )

                    command.sections.forEachIndexed { index, section ->
                        if (section.offset != 0) {
                            val sectionStartIndex =
                                command.startIndex + command.commandSize + (section.toDataType().length * index)
                            newDyibBuffer
                                .position(
                                    sectionStartIndex.toInt() +
                                        (16 * 2) + // skip names
                                        (if (machHeader.is32bit) 8 else 4) * 2, // skip address and size
                                ).putInt((cumulativeFileSize + (section.address - command.vMaddress)).toInt())
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
                    if (command.commandType !in handledLinkCommands) return
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

        fun <T : LoadCommand> writeDataToLinkedit(
            command: T,
            pointerAlignAfter: Boolean = true,
            preWriteCommandFixup: (T) -> Unit,
        ) {
            preWriteCommandFixup(command)
            val bytesToWrite =
                byteProviderForCacheFileContainingDylib.readBytes(
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

        val readerForSymbolTable = BinaryReader(byteProviderForCacheFileContainingDylib, true)
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
            newLinkeditSegmentCommand.startIndex,
            machHeader,
            fileSize = newLinkeditSegmentBuffer.position().toLong(),
            vmSize = ((newLinkEditFileSize + 4095) and (4096).inv()).toLong(),
        )
    }
}

class SharedCacheExtractor(
    private val dscFileSystem: GADyldCacheFileSystem,
    // 100 MiB default
    private val maxDylibSize: Int = 1024 * 1024 * 100,
) {
    fun extractDylib(originalDyibByteProvider: ByteProvider): ByteProvider {
        var bufferForExtractedDylib: ByteBuffer = ByteBuffer.allocate(maxDylibSize).order(ByteOrder.LITTLE_ENDIAN)

        copyAllSegmentsExceptLINKEDIT(
            originalDyibByteProvider,
            bufferForExtractedDylib,
        )

        val positionWhereLINKEDITShouldStart = bufferForExtractedDylib.position()

        val bufferForNewLinkeditSegment = ByteBuffer.allocate(1 shl 20)

        val linkeditOptimizer =
            LinkeditOptimizer(
                dscFileSystem,
                originalDyibByteProvider,
                bufferForExtractedDylib,
            )
        linkeditOptimizer.optimizeLoadCommands()

        linkeditOptimizer.optimizeLinkedit(bufferForNewLinkeditSegment)

        bufferForExtractedDylib
            .position(positionWhereLINKEDITShouldStart)
            .put(bufferForNewLinkeditSegment.array())

        val finalBytes = ByteArray(bufferForExtractedDylib.position())
        bufferForExtractedDylib.get(0, finalBytes)
        return ByteArrayProvider(finalBytes)
    }

    /**
     * Copies all segments from [originalDyibByteProvider] into [bufferForExtractedDylib] except `__LINKEDIT` and
     *  also moved the buffer position to point to after all the copied segments.
     */
    private fun copyAllSegmentsExceptLINKEDIT(
        originalDyibByteProvider: ByteProvider,
        bufferForExtractedDylib: ByteBuffer,
    ) {
        val originalMachHeader = MachHeader(originalDyibByteProvider).parse()

        // [toMutableList] implicitly makes a copy, so we don't have to worry about mutating the original list.
        val segmentsToCopy = originalMachHeader.allSegments.toMutableList()
        val linkEditSegment =
            segmentsToCopy
                .indexOfFirst { it.segmentName == "__LINKEDIT" }
                .takeIf { it != -1 }
                ?.let { segmentsToCopy.removeAt(it) } // __LINKEDIT is handled separately

        for (segment in segmentsToCopy) {
            bufferForExtractedDylib.put(
                originalDyibByteProvider.readBytes(
                    segment.fileOffset,
                    segment.fileSize,
                ),
            )
        }
    }
}

class LinkeditOptimizer(
    private val dscFileSystem: GADyldCacheFileSystem,
    private val originalDyibByteProvider: ByteProvider,
    private val bufferForExtractedDylib: ByteBuffer,
) {
    var originalLinkeditSegmentCommand: SegmentCommand? = null
    var textOffsetInCache: Long? = null
    var originalSymbolTableCommand: SymbolTableCommand? = null
    var originalDynamicSymbolTableCommand: DynamicSymbolTableCommand? = null
    var originalFunctionStartsCommand: FunctionStartsCommand? = null
    var originalDataInCodeCommand: DataInCodeCommand? = null

    var exportsTrie: ExportTrie? = null

    var reexportDeps = setOf<Int>()

    fun optimizeLoadCommands() {
        val originalMachHeader = MachHeader(originalDyibByteProvider).parse()
        val originalDylibReader = BinaryReader(originalDyibByteProvider, true)
        val dscReader = BinaryReader(dscFileSystem.fsByteProvider!!, true)

        var cumulativeFileSize = 0L
        var depIndex = 0

        originalDylibReader.pointerIndex = originalMachHeader.toDataType().length.toLong() // Start reading after the header.

        repeat(originalMachHeader.numberOfCommands) {
            val command =
                LoadCommandFactory.getLoadCommand(originalDylibReader, originalMachHeader, null)

            // Not sure why this is needed, but it seems to break without this. This ensures our reader points to
            //  the start of the next command on our next go around.
            originalDylibReader.pointerIndex = command.startIndex + command.commandSize

            // `dsc_extractor` matches on the command type, we match on the command class (and type if necessary).
            when (command) {
                is SegmentCommand -> {
                    val newFileOffset = cumulativeFileSize
                    val newFileSize = command.vMsize

                    if (command.segmentName == "__TEXT") {
                        textOffsetInCache =
                            command.vMaddress - dscFileSystem.rootHeader.unslidLoadAddress()
                    }

                    if (command.segmentName == "__LINKEDIT") {
                        originalLinkeditSegmentCommand = command
                    }

                    // We're lucky Ghidra gives us this "serialization" method.
                    val newCommandBytes =
                        SegmentCommand.create(
                            originalMachHeader.magic,
                            command.segmentName,
                            command.vMaddress,
                            command.vMsize,
                            newFileOffset,
                            newFileSize,
                            command.maxProtection,
                            command.initProtection,
                            command.numberOfSections,
                            command.flags,
                        )

                    // The [SegmentCommand.create] method does not include the correct command size if the segment
                    //  has sections (which they basically all do), so we need to copy the original size back into
                    //  the bytes before writing them to the new dylib buffer.
                    ByteBuffer
                        .allocate(Int.SIZE_BYTES)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .putInt(command.commandSize)
                        .array()
                        .copyInto(newCommandBytes, Int.SIZE_BYTES * 1)

                    bufferForExtractedDylib.put(command.startIndex.toInt(), newCommandBytes)

                    originalDylibReader.pointerIndex = command.startIndex + newCommandBytes.size
                    repeat(command.numberOfSections) {
                        val sectionStartIndex = originalDylibReader.pointerIndex
                        val section = Section(originalDylibReader, originalMachHeader.is32bit)
                        val newOffset =
                            section.offset.takeIf { it == 0 }
                                ?: (cumulativeFileSize + section.address + command.vMaddress).toInt()

                        fun Section.serialize(newOffset: Int): ByteArray {
                            val buffer =
                                ByteBuffer
                                    .allocate(this.toDataType().length)
                                    .order(ByteOrder.LITTLE_ENDIAN)
                            buffer.put(this.sectionName.toByteArray())
                            repeat(16 - this.sectionName.length) { buffer.put(0x00) }
                            buffer.put(this.segmentName.toByteArray())
                            repeat(16 - this.segmentName.length) { buffer.put(0x00) }
                            if (originalMachHeader.is32bit) {
                                buffer.putInt(this.address.toInt())
                                buffer.putInt(this.size.toInt())
                            } else {
                                buffer.putLong(this.address)
                                buffer.putLong(this.size)
                            }
                            buffer.putInt(newOffset)
                            buffer.putInt(this.align)
                            buffer.putInt(this.relocationOffset)
                            buffer.putInt(this.numberOfRelocations)
                            buffer.putInt(reserved1)
                            buffer.putInt(reserved2)
                            if (!originalMachHeader.is32bit) buffer.putInt(reserved3)
                            return buffer.array()
                        }
                        val sectionBytes = section.serialize(newOffset)
                        bufferForExtractedDylib.put(sectionStartIndex.toInt(), sectionBytes)
                    }
                    cumulativeFileSize += newFileSize
                }
                is DyldInfoCommand -> {
                    if (command.commandType != LoadCommandTypes.LC_DYLD_INFO_ONLY) return@repeat

                    fun DyldInfoCommand.serializeForExtractor(): ByteArray {
                        val buffer = ByteBuffer.allocate(this.commandSize).order(ByteOrder.LITTLE_ENDIAN)
                        buffer.putInt(command.commandType)
                        buffer.putInt(command.commandSize)
                        // rebase offset and size
                        buffer.putInt(0)
                        buffer.putInt(0)
                        // bind offset and size
                        buffer.putInt(0)
                        buffer.putInt(0)
                        // weak bind offset and size
                        buffer.putInt(0)
                        buffer.putInt(0)
                        // lazy bind offset and size
                        buffer.putInt(0)
                        buffer.putInt(0)
                        // export offset and size
                        buffer.putInt(0)
                        buffer.putInt(0)
                        return buffer.array()
                    }
                    exportsTrie = command.exportTrie
                    bufferForExtractedDylib.put(command.startIndex.toInt(), command.serializeForExtractor())
                }
                is DyldExportsTrieCommand -> {
                    fun DyldExportsTrieCommand.serializeForExtractor(): ByteArray {
                        val buffer = ByteBuffer.allocate(this.commandSize).order(ByteOrder.LITTLE_ENDIAN)
                        buffer.putInt(command.commandType)
                        buffer.putInt(command.commandSize)
                        // data offset and size
                        buffer.putInt(0)
                        buffer.putInt(0)
                        return buffer.array()
                    }
                    exportsTrie = command.exportTrie
                    bufferForExtractedDylib.put(command.startIndex.toInt(), command.serializeForExtractor())
                }
                is SymbolTableCommand -> this.originalSymbolTableCommand = command
                is DynamicSymbolTableCommand -> this.originalDynamicSymbolTableCommand = command
                is FunctionStartsCommand -> this.originalFunctionStartsCommand = command
                is DataInCodeCommand -> this.originalDataInCodeCommand = command
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
                    if (command.commandType !in handledLinkCommands) return
                    depIndex++
                    if (command.commandType == LoadCommandTypes.LC_REEXPORT_DYLIB) reexportDeps += depIndex
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
                else -> return@repeat
            }
        }
    }

    /**
     * Builds a new `__LINKEDIT` segment in [bufferForNewLinkeditSegment].
     */
    fun optimizeLinkedit(bufferForNewLinkeditSegment: ByteBuffer) {
        // Copy the segment commands into new values to stop the compiler from complaining when we use them later.
        val originalLinkeditSegmentCommandCopy =
            originalLinkeditSegmentCommand ?: return
        val originalSymbolTableCommandCopy =
            originalSymbolTableCommand ?: return
        val originalDynamicSymbolTableCommandCopy =
            originalDynamicSymbolTableCommand ?: return

        // This function makes heavy use of the original load commands, and the offsets to them. This should be
        //  fine, as we didn't adjust the offsets previously. It's also what `dsc_extractor` seems to do.

        fun <T : LoadCommand> writeDataToLinkedit(
            command: T,
            pointerAlignAfter: Boolean = true,
            preWriteCommandFixup: (T) -> Unit,
        ) {
            preWriteCommandFixup(command)
            bufferForNewLinkeditSegment.put(
                originalDyibByteProvider.readBytes(
                    command.linkerDataOffset.toLong(),
                    command.linkerDataSize.toLong(),
                ),
            )
            if (pointerAlignAfter) {
                val pointerSize = if (MachHeader(originalDyibByteProvider).is32bit) 4 else 8
                while (
                    (
                        (
                            originalLinkeditSegmentCommandCopy.fileOffset +
                                bufferForNewLinkeditSegment.position()
                        ) % pointerSize
                    ).toInt() != 0
                ) {
                    bufferForNewLinkeditSegment.put(0x00)
                }
            }
        }

        fun writeLinkeditCommandData(
            command: LinkEditDataCommand,
            pointerAlignAfter: Boolean = true,
        ) {
            writeDataToLinkedit(command, pointerAlignAfter) {
                val offsetForLinkeditCommandData = bufferForNewLinkeditSegment.position()
                bufferForExtractedDylib
                    .position(it.startIndex.toInt())
                    .putInt(it.commandType)
                    .putInt(it.commandSize)
                    .putInt(originalLinkeditSegmentCommandCopy.fileOffset.toInt() + offsetForLinkeditCommandData)
                    .putInt(it.linkerDataSize)
            }
        }

        originalFunctionStartsCommand?.let { writeLinkeditCommandData(it) }
        originalDataInCodeCommand?.let { writeLinkeditCommandData(it) }

        // Write the Symbol Table
        // TODO: Include exports in the symbol table

        val nonReExportedExports =
            exportsTrie?.exports?.filter {
                val exportKind = (it.flags and DyldInfoCommandConstants.EXPORT_SYMBOL_FLAGS_KIND_MASK.toLong())
                if (exportKind != DyldInfoCommandConstants.EXPORT_SYMBOL_FLAGS_KIND_REGULAR.toLong()) {
                    return@filter false
                }
                // The `dsc_extractor` code actually uses the inverse of this check, but that honestly doesn't
                //  make any sense whatsoever so we invert it here.
                if ((it.flags and DyldInfoCommandConstants.EXPORT_SYMBOL_FLAGS_REEXPORT.toLong()) != 0L) {
                    return@filter false
                }
                // I'm not really sure what this is, but it's my best attempt at what `dsc_extractor` does here.
                if (reexportDeps.contains(it.other.toInt())) {
                    return@filter false
                }
                return@filter true
            } ?: listOf()

        val newSymbolCount = originalSymbolTableCommandCopy.numberOfSymbols + nonReExportedExports.size

        val offsetForSymbolTable = bufferForNewLinkeditSegment.position()
        writeDataToLinkedit(originalSymbolTableCommandCopy, pointerAlignAfter = false) {
            // No fixup yet, because we don't know all we need to know.
        }

        val offsetForDynamicSymbolTable = bufferForNewLinkeditSegment.position()

        writeDataToLinkedit(originalDynamicSymbolTableCommandCopy, pointerAlignAfter = false) {
            // Same here. We'll fix them both up at the end.
        }

        val offsetForStringPool = bufferForExtractedDylib.position()

        var symbolTableStringPool = "\u0000" // Per `dsc_extractor`: the first entry is always an empty string.

        // TODO: Build symbol strings

        // We need to pointer-align the string pool size.
        val pointerSize = if (MachHeader(originalDyibByteProvider).is32bit) 4 else 8
        while (symbolTableStringPool.length % pointerSize != 0) symbolTableStringPool += "\u0000"

        bufferForExtractedDylib.put(symbolTableStringPool.toByteArray())

        // Now we can finally fix up the symbol table command.
        originalSymbolTableCommandCopy.let {
            bufferForExtractedDylib
                .position(it.startIndex.toInt())
                .putInt(it.commandType)
                .putInt(it.commandSize)
                .putInt(offsetForSymbolTable)
                .putInt((it.numberOfSymbols))
                .putInt(offsetForStringPool)
                .putInt(symbolTableStringPool.length)
        }

        // We can also finally fix up the dynamic symbol table command.
        originalDynamicSymbolTableCommandCopy.let {
            bufferForExtractedDylib
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
                .putInt(offsetForDynamicSymbolTable)
                .putInt(it.indirectSymbolTableSize)
                .putInt(0)
                .putInt(0)
                .putInt(0)
                .putInt(0)
        }

        // Finally, we fix up the original `__LINKEDIT` segment command.
        originalLinkeditSegmentCommandCopy.let {
            // This is not the calculation that `dsc_extractor` does, but it's easier on us to do it this way.
            val newLinkEditFileSize = bufferForNewLinkeditSegment.position()
            bufferForExtractedDylib
                .position(it.startIndex.toInt())
                .putInt(it.commandType)
                .putInt(it.commandSize)
                .apply {
                    put(it.segmentName.toByteArray())
                    repeat(16 - it.segmentName.length) { put(0x00) }
                }.putInt(it.vMaddress.toInt())
                .putInt(((newLinkEditFileSize + 4095) and (4096).inv()))
                .putInt(it.fileOffset.toInt())
                .putInt(newLinkEditFileSize)
            // Keep everything else the same.
        }
    }
}
