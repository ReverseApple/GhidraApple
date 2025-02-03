package lol.fairplay.ghidraapple.loading

import ghidra.app.util.Option
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.LoadSpec
import ghidra.app.util.opinion.Loaded
import ghidra.app.util.opinion.MachoLoader
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.framework.model.Project
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.dyld.DSCFileSystem
import lol.fairplay.ghidraapple.dyld.DSCHelper
import lol.fairplay.ghidraapple.dyld.Dyld
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The Mach-O file loader for GhidraApple.
 */
class GAMachoLoader : MachoLoader() {
    private var wasUniversalBinary = false

    override fun getName(): String? = "(GhidraApple) " + super.getName()

    override fun getPreferredFileName(byteProvider: ByteProvider): String {
        val original = super.getPreferredFileName(byteProvider)

        // Handle special cases.

        if (byteProvider.fsrl.toStringPart().startsWith("universalbinary://")) {
            wasUniversalBinary = true
            // The FURL is two-fold: the path to the binary, and a path within the binary. We take the
            // former and extract the name (which will be the last path component, the binary name).
            val binaryName = byteProvider.fsrl.split()[0].name
            // We prefix with the binary name as the original name is just the architecture and CPU.
            return "$binaryName-$original"
        }

        // If no special case matched, return the original name.
        return original
    }

    override fun load(
        provider: ByteProvider,
        loadSpec: LoadSpec,
        options: List<Option?>,
        program: Program,
        monitor: TaskMonitor,
        log: MessageLog,
    ) {
        super.load(provider, loadSpec, options, program, monitor, log)
        // The executable format is named after the loader. However, Ghidra performs some checks against this name to
        // enable certain analyzers (so we have to give it a name it expects: the name of the built-in loader).
        program.executableFormat = MACH_O_NAME

        val fileSystem = FileSystemService.getInstance().getFilesystem(provider.fsrl.fs, null).filesystem

        // If the Mach-O was loaded with our custom dyld shared cache handler, we can do some more things with it.
        if (fileSystem is DSCFileSystem) {
            markupDyldCacheSource(program, fileSystem)
            val pointerRepointer = CachePointerRepointer(program, fileSystem.cacheHelper!!)
            pointerRepointer.repointSelectorReferences()
            pointerRepointer.repointOtherReferences()
            if (fileSystem.platform == Dyld.Platform.MACOS) {
                val cachedDylibLinker = CachedDylibImporter(program, fileSystem.cacheHelper!!)
                // Many dylibs are probably going to have pointers to this, so let's just map it.
                cachedDylibLinker.mapCachedDependency("/usr/lib/libobjc.A.dylib")
            }
        }

        var isBeingDebugged = System.getProperty("intellij.debug.agent") == "true"
        if (isBeingDebugged) {
            // Delete the cached byte provider after a successful load if the plugin is being debugged. We might be
            //  making changes to our extract code and want to see the results without having to fully restart.
            DSCFileSystem.fileByteProviderMap
                .keys
                .firstOrNull { it.path == provider.fsrl.path }
                ?.let {
                    DSCFileSystem.fileByteProviderMap.remove(it)
                }
        }
    }

    /**
     * At times, it might be useful to know what dyld shared cache a dylib came from. This function adds the platform
     * of the source shared cache to the program info (visible in the "About Program" dialog).
     */
    private fun markupDyldCacheSource(
        program: Program,
        fileSystem: DSCFileSystem,
    ) {
        val infoOptions = program.getOptions(Program.PROGRAM_INFO)
        infoOptions.setString("Extracted from dyld Shared Cache", fileSystem.platformPrettyNameWithVersion)
    }

    override fun postLoadProgramFixups(
        loadedPrograms: MutableList<Loaded<Program>>,
        project: Project,
        options: MutableList<Option>,
        messageLog: MessageLog,
        monitor: TaskMonitor,
    ) {
        super.postLoadProgramFixups(loadedPrograms, project, options, messageLog, monitor)
        for (loaded in loadedPrograms) {
            if (wasUniversalBinary) {
                // The actual program is wrapped, so we need to unwrap it.
                val program = loaded.domainObject

                // This will trigger [getPreferredFileName] above.
                val preferredName = loaded.name

                // We rename with the preferred name.
                program.withTransaction<Exception>("rename") {
                    program.name = preferredName
                }

                // After renaming, the programs will be in folders named after their original
                // names. To reduce redundancy, we move the programs to the parent folder.
                val originalFolderPath = loaded.projectFolderPath
                val newFolderPath =
                    originalFolderPath
                        .split("/")
                        // Filter out, potentially, the last, empty, element (if the path ended in "/").
                        .filterNot(String::isEmpty)
                        .dropLast(1) // Drop the last path component, leaving a path to the parent folder.
                        .joinToString("/")
                loaded.projectFolderPath = newFolderPath
                // Now that the program is up one folder, we can delete the original one.
                project.projectData.getFolder(originalFolderPath)?.delete()
            }
        }
    }
}

class CachePointerRepointer(
    private val program: Program,
    private val memoryHelper: DSCHelper,
) {
    private val memory = program.memory

//    private val addressFactory = program.addressFactory
    private val pointerSize = program.addressFactory.defaultAddressSpace.pointerSize

    private fun repointStringPointer(
        addressOfPointerToRepoint: Address,
        memoryBlockToSearch: MemoryBlock,
    ) {
        // Get the given pointer.
        val pointerBytes = ByteArray(pointerSize)
        val bytesCopied = memory.getBytes(addressOfPointerToRepoint, pointerBytes)
        if (bytesCopied != pointerSize) return
        var pointerValue =
            ByteBuffer
                .wrap(pointerBytes)
                .order(ByteOrder.LITTLE_ENDIAN)
                .long

        // Find the string it is pointing to.
        val string =
            memoryHelper.readMappedCString(pointerValue) ?: return

        var searchAddress = memoryBlockToSearch.addressRange.minAddress
        val stringBytes = string.toByteArray()
        do {
            run happy_path@{
                // It must be the start of a string (i.e. a null-terminated string precedes it).
                if (memory.getByte(searchAddress.subtract(1)) != 0x00.toByte()) return@happy_path
                // Loop through bytes to match string.
                for (i in stringBytes.indices) {
                    val possiblyMatchingByte = memoryBlockToSearch.getByte(searchAddress.add(i.toLong()))
                    if (possiblyMatchingByte != stringBytes[i]) return@happy_path
                }
                // We found the string! Now we re-point the pointer.
                val newPointerBytes =
                    ByteBuffer
                        .allocate(pointerSize)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .putLong(searchAddress.offset)
                        .array()
                memory.setBytes(addressOfPointerToRepoint, newPointerBytes)
            }
            searchAddress = searchAddress.add(1)
        } while // Iterate until the string we're searching for cannot fit in the remaining bytes.
        (searchAddress <= memoryBlockToSearch.addressRange.maxAddress.subtract(string.length.toLong()))
    }

    fun repointStringReferences(
        referencesBlock: MemoryBlock,
        stringsBlock: MemoryBlock,
    ) {
        var currentAddress = referencesBlock.addressRange.minAddress
        while (currentAddress <= referencesBlock.addressRange.maxAddress) {
            repointStringPointer(currentAddress, stringsBlock)
            currentAddress = currentAddress.add(pointerSize.toLong())
        }
    }

    fun repointSelectorReferences() {
        repointStringReferences(
            program.memory.getBlock("__objc_selrefs") ?: return,
            program.memory.getBlock("__objc_methname") ?: return,
        )
    }

    fun repointOtherReferences() {
        repointStringReferences(
            program.memory.getBlock("__objc_const") ?: return,
            program.memory.getBlock("__objc_methname") ?: return,
        )
    }
}

class CachedDylibImporter(
    private val program: Program,
    private val cacheHelper: DSCHelper,
) {
    val cachePointerRepointer = CachePointerRepointer(program, cacheHelper)

    private fun createBlockName(
        path: String,
        segmentName: String,
        sectionName: String?,
    ) = "$path -- $segmentName -- ${sectionName ?: "(no section)"}"

    private fun addBlockFromMappedCache(
        name: String,
        vmAddress: Long,
        vmSize: Long,
    ): MemoryBlock {
        vmSize
        val block =
            program.memory.createInitializedBlock(
                name,
                program.addressFactory.defaultAddressSpace.getAddress(vmAddress),
                vmSize,
                0x00.toByte(),
                null,
                false,
            )
        block.putBytes(block.addressRange.minAddress, cacheHelper.readMappedBytes(vmAddress, vmSize))
        return block
    }

    fun mapCachedDependency(path: String) {
        val header = cacheHelper.findMachHeaderForImage(path) ?: return
        val blocksAdded = mutableListOf<MemoryBlock>()
        for (segment in header.allSegments) {
            if (segment.vMsize == 0L) continue
            try {
                if (segment.sections.isEmpty()) {
                    blocksAdded +=
                        addBlockFromMappedCache(
                            createBlockName(path, segment.segmentName, null),
                            segment.vMaddress,
                            segment.vMsize,
                        )
                } else {
                    for (section in segment.sections) {
                        if (section.size == 0L) continue
                        if (section.segmentName != segment.segmentName) {
                            // This probably should never happen, but we want to know about it if it does.
                            println(
                                "($path) Section ${section.sectionName} claims to be in segment " +
                                    "${section.segmentName}, but is listed below ${segment.segmentName}.",
                            )
                        }
                        blocksAdded +=
                            addBlockFromMappedCache(
                                createBlockName(path, section.segmentName, section.sectionName),
                                section.address,
                                section.size,
                            )
                    }
                }
            } catch (e: Exception) {
                println("Failed to add segment: $e")
            }
        }
        repointStringReferencesPostMap(path)
    }

    private fun repointStringReferencesPostMap(path: String) {
        cachePointerRepointer.repointStringReferences(
            program.memory.getBlock(createBlockName(path, "__AUTH_CONST", "__objc_selrefs")) ?: return,
            program.memory.getBlock(createBlockName(path, "__TEXT", "__objc_methname")) ?: return,
        )
        cachePointerRepointer.repointStringReferences(
            program.memory.getBlock(createBlockName(path, "__AUTH_CONST", "__objc_const")) ?: return,
            program.memory.getBlock(createBlockName(path, "__TEXT", "__objc_methname")) ?: return,
        )
    }
}
