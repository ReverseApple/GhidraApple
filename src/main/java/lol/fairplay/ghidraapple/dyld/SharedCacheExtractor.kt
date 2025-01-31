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

    var exportsTrieOffset = 0
    var exportsTrieSize = 0

    var reexportDeps = setOf<Int>()

    fun optimizeLoadCommands() {
        val originalMachHeader = MachHeader(originalDyibByteProvider).parse()
        val originalDylibReader = BinaryReader(originalDyibByteProvider, true)

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
                    exportsTrieOffset = command.exportOffset
                    exportsTrieSize = command.exportSize
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
                    exportsTrieOffset = command.linkerDataOffset
                    exportsTrieSize = command.linkerDataSize
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

        fun writeLinkerData(
            command: LinkEditDataCommand,
            pointerAlignAfter: Boolean = true,
        ) {
            val offsetForLinkerData = bufferForExtractedDylib.position()
            command.let {
                bufferForNewLinkeditSegment.put(
                    originalDyibByteProvider.readBytes(
                        it.linkerDataOffset.toLong(),
                        it.linkerDataSize.toLong(),
                    ),
                )
                bufferForExtractedDylib
                    .position(it.startIndex.toInt())
                    .putInt(it.commandType)
                    .putInt(it.commandSize)
                    .putInt(originalLinkeditSegmentCommandCopy.fileOffset.toInt() + offsetForLinkerData)
                    .putInt(it.linkerDataSize)
            }
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

        // This function makes heavy use of the original load commands, and the offsets to them. This should be
        //  fine, as we didn't adjust the offsets previously. It's also what `dsc_extractor` seems to do.

        originalFunctionStartsCommand?.let { writeLinkerData(it) }
        originalDataInCodeCommand?.let { writeLinkerData(it) }

//
//        // Write the Symbol Table
//        // TODO: Include exports in the symbol table
//
//        val newSymbolTableOffset = bufferForNewLinkeditSegment.position()
//
//        originalSymbolTableCommandCopy.let {
//            bufferForNewLinkeditSegment.put(
//                originalDyibByteProvider.readBytes(
//                    it.linkerDataOffset.toLong(),
//                    it.linkerDataSize.toLong(),
//                ),
//            )
//            bufferForExtractedDylib
//                .position(it.startIndex.toInt())
//                .putInt(it.commandType)
//                .putInt(it.commandSize)
//                .putInt(originalLinkeditSegmentCommandCopy.fileOffset.toInt() + newSymbolTableOffset)
//                .putInt(it.linkerDataSize)
//        }
    }
}
