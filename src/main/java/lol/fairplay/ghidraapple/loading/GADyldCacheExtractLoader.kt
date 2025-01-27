package lol.fairplay.ghidraapple.loading

import ghidra.app.util.Option
import ghidra.app.util.bin.ByteProvider
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
        super.load(provider, loadSpec, options, program, monitor, log)
        if (provider == null || program == null) return

        // The executable format is named after the loader. However, Ghidra performs some checks against this name to
        // enable certain analyzers (so we have to give it a name it expects: the name of a built-in loader).
        program.executableFormat = MACH_O_NAME

        val fileSystem = FileSystemService.getInstance().getFilesystem(provider.fsrl.fs, null).filesystem
        if (fileSystem !is GADyldCacheFileSystem) return

        markupDyldCacheSource(program, fileSystem)
        repointSelectorReferences(program, fileSystem)
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
     * over the selector pointers and point them to the same strings where they exist inside the dylib.
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
    }
}
