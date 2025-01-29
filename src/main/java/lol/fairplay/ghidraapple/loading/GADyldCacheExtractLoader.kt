@file:Suppress("ktlint:standard:no-wildcard-imports")

package lol.fairplay.ghidraapple.loading

import ghidra.app.util.Option
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteArrayProvider
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.MachHeader
import ghidra.app.util.bin.format.macho.Section
import ghidra.app.util.bin.format.macho.commands.*
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.DyldCacheExtractLoader
import ghidra.app.util.opinion.LoadSpec
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.filesystems.GADyldCacheFileSystem
import java.nio.ByteBuffer
import java.nio.ByteOrder

class GADyldCacheExtractLoader : DyldCacheExtractLoader() {
    override fun getName(): String {
        // We need a new name to differentiate our loader from the built-in one.
        return "(GhidraApple) " + super.getName()
    }

    override fun load(
        provider: ByteProvider?,
        loadSpec: LoadSpec?,
        options: MutableList<Option>?,
        program: Program?,
        monitor: TaskMonitor?,
        log: MessageLog?,
    ) {
        if (provider == null || program == null) return

        // The executable format is named after the loader. However, Ghidra performs some checks against this name to
        // enable certain analyzers (so we have to give it a name it expects: the name of a built-in loader).
        program.executableFormat = MACH_O_NAME

        val fileSystem = FileSystemService.getInstance().getFilesystem(provider.fsrl.fs, null).filesystem
        if (fileSystem !is GADyldCacheFileSystem) return

        val newByteProvider = extractDyldFromDSC(provider, fileSystem)
        super.load(newByteProvider, loadSpec, options, program, monitor, log)
        markupDyldCacheSource(program, fileSystem)
        repointSelectorReferences(program, fileSystem)
        addDylibsToProgram(program, fileSystem, provider)
        mapDyldSharedCacheToProgram(program, fileSystem, monitor)
    }

    /**
     * The dyld project includes a library called `dsc_extractor`. The logic of this function is largely copied from
     * that library. The logic is copied to avoid having to link in the dyld project to this plugin.
     */
    private fun extractDyldFromDSC(
        provider: ByteProvider,
        fileSystem: GADyldCacheFileSystem,
    ): ByteProvider {
        val machHeader = MachHeader(provider).parse()

        // [toMutableList] implicitly makes a copy, so we don't have to worry about mutating the original list.
        val segmentsToCopy = machHeader.allSegments.toMutableList()
        segmentsToCopy.removeIf { it.segmentName == "__LINKEDIT" } // __LINKEDIT is handled separately

        val newBytes =
            segmentsToCopy.fold(byteArrayOf()) { acc, segment ->
                acc +
                    provider.readBytes(
                        segment.fileOffset,
                        segment.fileSize,
                    )
            }

        val newProvider = ByteArrayProvider(newBytes) // TODO: Make this use [copyOf] when done.

        val newReader = BinaryReader(newProvider, true)
        newReader.pointerIndex = machHeader.size // Skip past the header

        var cumulativeFileSize = 0L
        var exportsTrieOffset = 0
        var exportsTrieSize = 0

        var textOffsetInCache: Long? = null

        var symTab: SymbolTableCommand? = null
        var dynamicSymTab: DynamicSymbolTableCommand? = null
        var functionStarts: FunctionStartsCommand? = null
        var dataInCode: DataInCodeCommand? = null
        repeat(machHeader.numberOfCommands) {
            val commandStartIndex = newReader.pointerIndex
            val command =
                LoadCommandFactory
                    .getLoadCommand(newReader, machHeader, fileSystem.splitDyldCache)

            newReader.pointerIndex -= command.commandSize // Pull the pointer back to the start of the command.

            // `dsc_extractor` matches on the command type, we match on the command class (and type if necessary).
            when (command) {
                is SegmentCommand -> {
                    val newFileOffset = cumulativeFileSize
                    val newFileSize = command.vMsize

                    if (command.segmentName == "__TEXT") {
                        textOffsetInCache =
                            command.vMaddress - fileSystem.rootHeader.unslidLoadAddress()
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
                    newCommandBytes.copyInto(newBytes, newReader.pointerIndex.toInt())

                    newReader.pointerIndex += newCommandBytes.size
                    repeat(command.numberOfSections) {
                        val section = Section(newReader, machHeader.is32bit)
                        // Pull the pointer back to before the section.
                        newReader.pointerIndex -= section.toDataType().length
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
                        sectionBytes.copyInto(newBytes, newReader.pointerIndex.toInt())
                        newReader.pointerIndex += sectionBytes.size // Push the pointer forwards.
                    }
                    cumulativeFileSize += newFileSize
                    newReader.pointerIndex -= command.commandSize // Pull the pointer back to the start of the command.
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
                    command.serializeForExtractor().copyInto(newBytes, newReader.pointerIndex.toInt())
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
                    command.serializeForExtractor().copyInto(newBytes, newReader.pointerIndex.toInt())
                }
                else -> return@repeat
            }

            newReader.pointerIndex = commandStartIndex + command.commandSize
        }
        return ByteArrayProvider(newBytes)
    }

    /**
     * At times, it might be useful to know what dyld shared cache a dylib came from. This function adds the platform
     * of the source shared cache to the program info (visible in the "About Program" dialog).
     */
    private fun markupDyldCacheSource(
        program: Program,
        fileSystem: GADyldCacheFileSystem,
    ) {
        val infoOptions = program.getOptions(Program.PROGRAM_INFO)
        val cachePlatform = fileSystem.platform?.prettyName ?: "unknownOS"
        val cacheVersion = fileSystem.osVersion ?: "?.?.?"
        infoOptions.setString("Dyld Shared Cache Platform", "$cachePlatform $cacheVersion")
    }

    /**
     * The dyld shared cache building process puts all selectors into an array and points all selector pointers into
     * that array. However, those same strings should still exist in the extracted dylib. This function will iterate
     * over the selector pointers and re-point them to the same strings where they exist inside the dylib. This will
     * avoid us having to map the entire selector array into the Program's memory.
     */
    private fun repointSelectorReferences(
        program: Program,
        fileSystem: GADyldCacheFileSystem,
    ) {
        val memory = program.memory
        val addressFactory = program.addressFactory

        val selRefs = memory.blocks.firstOrNull { it.name == "__objc_selrefs" }
        val methName = memory.blocks.firstOrNull { it.name == "__objc_methname" }
        if (selRefs == null || methName == null) return

        fun findStringInMethName(string: String): Address? {
            var currentAddress = methName.addressRange.minAddress
            val stringBytes = string.toByteArray()
            do {
                run happy_path@{
                    // It must be the start of a string (i.e. a null-terminated string precedes it).
                    if (memory.getByte(currentAddress.subtract(1)) != 0x00.toByte()) return@happy_path
                    // Loop through bytes to match string.
                    for (i in stringBytes.indices) {
                        if (methName.getByte(currentAddress.add(i.toLong())) != stringBytes[i]) return@happy_path
                    }
                    return currentAddress
                }
                currentAddress = currentAddress.add(1)
            } while // Iterate until the string cannot fit
            (currentAddress <= methName.addressRange.maxAddress.subtract(string.length.toLong()))

            return null // There was no match.
        }

        val pointerSize = addressFactory.defaultAddressSpace.pointerSize

        var currentAddress = selRefs.addressRange.minAddress

        while (currentAddress <= selRefs.addressRange.maxAddress) {
            run happy_path@{
                // Get the given pointer.
                val pointerBytes = ByteArray(pointerSize)
                val bytesCopied = memory.getBytes(currentAddress, pointerBytes)
                if (bytesCopied != pointerSize) return@happy_path
                val pointerValue = ByteBuffer.wrap(pointerBytes).order(ByteOrder.LITTLE_ENDIAN).long

                // Find the string it is pointing to.
                val string = fileSystem.readMappedCString(pointerValue) ?: return@happy_path

                // Find the same string in `__objc_methname`.
                val inDylibAddress = findStringInMethName(string) ?: return@happy_path

                // Re-point the pointer.
                val newPointerBytes =
                    ByteBuffer
                        .allocate(pointerSize)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .putLong(inDylibAddress.offset)
                        .array()
                memory.setBytes(currentAddress, newPointerBytes)
            }
            currentAddress = currentAddress.add(pointerSize.toLong())
        }

        // Tell Ghidra that these pointers won't be updating anymore so it can perform optimizations.
        selRefs.isWrite = false
    }

    private fun addDylibsToProgram(
        program: Program,
        fileSystem: GADyldCacheFileSystem,
        byteProvider: ByteProvider,
    ) {
        val machHeader = MachHeader(byteProvider)
        machHeader.parse(fileSystem.splitDyldCache)
        val dylibs =
            machHeader.loadCommands
                .filterIsInstance<DynamicLibraryCommand>()
                .map { it.dynamicLibrary }
        for (dylib in dylibs) {
            val matchingCachedDylib =
                fileSystem
                    .rootHeader.mappedImages
                    .firstOrNull { it.path == dylib.name.string }
            println(matchingCachedDylib)
        }
    }

    // TODO: Remove this when no longer needed.
    private fun mapDyldSharedCacheToProgram(
        program: Program,
        fileSystem: GADyldCacheFileSystem,
        monitor: TaskMonitor?,
    ) {
        var index = 0

        fileSystem.getMappings().forEach { (mapping, bytes) ->
            try {
                val baseAddress = program.addressFactory.defaultAddressSpace.getAddress(mapping.address)
                val block =
                    program.memory.createInitializedBlock(
                        "DSC Mapping ${++index}",
                        baseAddress,
                        mapping.size,
                        (0).toByte(),
                        monitor,
                        false,
                    )
                block.putBytes(baseAddress, bytes)
            } catch (_: Exception) {
            }
        }
    }
}
