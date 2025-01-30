package lol.fairplay.ghidraapple.dyld

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.app.util.bin.format.macho.Section
import ghidra.app.util.bin.format.macho.commands.DataInCodeCommand
import ghidra.app.util.bin.format.macho.commands.DyldExportsTrieCommand
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommand
import ghidra.app.util.bin.format.macho.commands.DynamicLinkerCommand
import ghidra.app.util.bin.format.macho.commands.DynamicSymbolTableCommand
import ghidra.app.util.bin.format.macho.commands.FunctionStartsCommand
import ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand
import ghidra.app.util.bin.format.macho.commands.LoadCommandFactory
import ghidra.app.util.bin.format.macho.commands.LoadCommandTypes
import ghidra.app.util.bin.format.macho.commands.SegmentCommand
import ghidra.app.util.bin.format.macho.commands.SymbolTableCommand
import lol.fairplay.ghidraapple.filesystems.GADyldCacheFileSystem
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.collections.plus

/**
 * The dyld project includes a library called `dsc_extractor`. The logic in this file is largely copied from
 * that library. The logic is copied as `dsc_extractor` is not portable to non-Apple platforms.
 */

class SharedCacheExtractor(
    private val dscFileSystem: GADyldCacheFileSystem,
    private val maxDylibSize: Int = 1024 * 1024 * 100, // 100 MiB
) {
    fun extractDylib(originalDyibByteProvider: ByteProvider): ByteProvider {
        var bufferForExtractedDylib: ByteBuffer = ByteBuffer.allocate(maxDylibSize)

        copyAllSegmentsExceptLINKEDIT(originalDyibByteProvider, bufferForExtractedDylib)
        val positionWhereLINKEDITShouldStart = bufferForExtractedDylib.position()

        val bufferForNewLinkeditSection = ByteBuffer.allocate(1 shl 20)

        val linkeditOptimizer =
            LinkeditOptimizer(
                dscFileSystem,
                originalDyibByteProvider,
                bufferForExtractedDylib,
            )
        linkeditOptimizer.optimizeLoadCommands()
        linkeditOptimizer.optimizeLinkedit(bufferForNewLinkeditSection)

        bufferForExtractedDylib
            .position(positionWhereLINKEDITShouldStart)
            .put(bufferForNewLinkeditSection)

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
    var linkedit: Pair<SegmentCommand, Int>? = null

    var textOffsetInCache: Long? = null

    var symTab: Pair<SymbolTableCommand, Int>? = null
    var dynamicSymTab: Pair<DynamicSymbolTableCommand, Int>? = null
    var functionStarts: Pair<FunctionStartsCommand, Int>? = null
    var dataInCode: Pair<DataInCodeCommand, Int>? = null

    var exportsTrieOffset = 0
    var exportsTrieSize = 0

    var reexportDeps = setOf<Int>()

    fun optimizeLoadCommands() {
        val machHeader = MachHeader(originalDyibByteProvider).parse()
        val dylibReader = BinaryReader(originalDyibByteProvider, true)

        var cumulativeFileSize = 0L
        var depIndex = 0

        repeat(machHeader.numberOfCommands) {
            val commandStartIndex = dylibReader.pointerIndex
            val command =
                LoadCommandFactory
                    .getLoadCommand(dylibReader, machHeader, dscFileSystem.splitDyldCache)

            // `dsc_extractor` matches on the command type, we match on the command class (and type if necessary).
            when (command) {
                is SegmentCommand -> {
                    val newFileOffset = cumulativeFileSize
                    val newFileSize = command.vMsize

                    if (command.segmentName == "__TEXT") {
                        textOffsetInCache =
                            command.vMaddress - dscFileSystem.rootHeader.unslidLoadAddress()
                    }

                    // We're lucky Ghidra gives us this "serialization" method.
                    val newCommandBytes =
                        SegmentCommand.create(
                            machHeader.magic,
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

                    bufferForExtractedDylib.put(commandStartIndex.toInt(), newCommandBytes)

                    dylibReader.pointerIndex += commandStartIndex + newCommandBytes.size
                    repeat(command.numberOfSections) {
                        val sectionStartIndex = dylibReader.pointerIndex
                        val section = Section(dylibReader, machHeader.is32bit)
                        val newOffset =
                            section.offset.takeIf { it == 0 }
                                ?: (cumulativeFileSize + section.address + command.vMaddress).toInt()

                        fun Section.serialize(newOffset: Int): ByteArray {
                            val buffer =
                                ByteBuffer
                                    .allocate(this.toDataType().length)
                                    .order(ByteOrder.LITTLE_ENDIAN)
                            buffer.put(this.sectionName.toByteArray())
                            repeat(this.sectionName.length - 16) { buffer.put(0x00) }
                            buffer.put(this.segmentName.toByteArray())
                            repeat(this.segmentName.length - 16) { buffer.put(0x00) }
                            if (machHeader.is32bit) {
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
                            if (!machHeader.is32bit) buffer.putInt(reserved3)
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
                    exportsTrieOffset = command.exportOffset
                    exportsTrieSize = command.exportSize
                    bufferForExtractedDylib.put(commandStartIndex.toInt(), command.serializeForExtractor())
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
                    exportsTrieOffset = command.linkerDataOffset
                    exportsTrieSize = command.linkerDataSize
                    bufferForExtractedDylib.put(commandStartIndex.toInt(), command.serializeForExtractor())
                }
                is SymbolTableCommand -> this.symTab = Pair(command, commandStartIndex.toInt())
                is DynamicSymbolTableCommand -> this.dynamicSymTab = Pair(command, commandStartIndex.toInt())
                is FunctionStartsCommand -> this.functionStarts = Pair(command, commandStartIndex.toInt())
                is DataInCodeCommand -> this.dataInCode = Pair(command, commandStartIndex.toInt())
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
     * Builds a new `__LINKEDIT` section and writes it to [bufferForExtractedDylib], moving the position of the
     *  buffer to the end of the newly-written `__LINKEDIT` section.
     */
    fun optimizeLinkedit(bufferForNewLinkeditSection: ByteBuffer) {
        if (linkedit == null) return
        if (symTab == null) return
        if (dynamicSymTab == null) return

        val linkeditSegmentCommand = linkedit!!.first
        val linkeditBaseOffset = linkedit!!.second

        val newFunctionStartsOffset = bufferForNewLinkeditSection.position()
        functionStarts?.let {
            val functionStartsCommand = it.first
            val functionStartsOffset = it.second
            val baseOffset = linkeditBaseOffset + functionStartsCommand.linkerDataOffset
            val newFunctionStartsSize = functionStartsCommand.linkerDataSize
            bufferForExtractedDylib.put(
                originalDyibByteProvider
                    .readBytes(baseOffset.toLong(), (baseOffset + newFunctionStartsSize).toLong()),
            )
//            bufferForExtractedDylib
//                .position(functionStartsOffset)
//                .putInt(functionStartsCommand.commandType)
//                .putInt(functionStartsCommand.commandSize)
//                .putInt(linkeditBaseOffset.toInt())
//                .putInt(newFunctionStartsSize)
        }
        val pointerSize = if (MachHeader(originalDyibByteProvider).is32bit) 4 else 8
        while (
            (linkeditSegmentCommand.fileOffset + bufferForNewLinkeditSection.position() % pointerSize).toInt() != 0
        ) {
            bufferForNewLinkeditSection.put(0x00)
        }

        val newDataInCodeOffset = bufferForExtractedDylib.position()
        dataInCode?.let {
            val dataInCodeCommand = it.first
            val dataInCodeOffset = it.second
            val baseOffset = linkeditBaseOffset + dataInCodeCommand.linkerDataOffset
            val newFunctionStartsSize = dataInCodeCommand.linkerDataSize
            bufferForExtractedDylib.put(
                originalDyibByteProvider
                    .readBytes(baseOffset.toLong(), (baseOffset + newFunctionStartsSize).toLong()),
            )
//            bufferForExtractedDylib
//                .position(functionStartsOffset)
//                .putInt(functionStartsCommand.commandType)
//                .putInt(functionStartsCommand.commandSize)
//                .putInt(linkeditBaseOffset!!.toInt())
//                .putInt(newFunctionStartsSize)
        }
        // TODO: Finish building out __LINKEDIT section.
    }
}
