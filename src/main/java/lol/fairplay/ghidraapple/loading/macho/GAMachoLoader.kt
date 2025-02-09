package lol.fairplay.ghidraapple.loading.macho

import ghidra.app.util.Option
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.LoadSpec
import ghidra.app.util.opinion.Loaded
import ghidra.app.util.opinion.MachoLoader
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.framework.model.Project
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.dyld.DSCFileSystem
import lol.fairplay.ghidraapple.dyld.DSCHelper

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
            // If the selector references block isn't read-only, Ghidra won't apply optimizations
            //  that are required for our analyzers to work properly.
            val selRefs = program.memory.getBlock("__objc_selrefs")
            selRefs.isRead = true
            selRefs.isWrite = false
            selRefs.isExecute = false

            markupProgramInfo(program, fileSystem)

            // Map additional data into the program
            val mappingMapper = CacheMappingMapper(program, fileSystem.cacheHelper!!)
            mappingMapper.mapStubOptimizations()
            val mappedROBlocks = mappingMapper.mapReadOnlyData()
            // The function above is meant to capture the Objective-C optimizations, but only works on
            //  more recent caches. If we failed to map anything, we fall back to the below function.
            if (mappedROBlocks.isEmpty()) mappingMapper.mapLibObjCOptimizations()
        }
    }

    /**
     * Adds information about the source cache to the program info (visible in the "About Program" dialog).
     */
    private fun markupProgramInfo(
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

class CacheMappingMapper(
    private val program: Program,
    private val cacheHelper: DSCHelper,
) {
    companion object {
        private const val STUBS_PROGRAM_TREE_NAME = "Cached Stubs"
        private const val READ_ONLY_DATA_PROGRAM_TREE_NAME = "Cached Read-Only Data"
    }

    private fun mapMappingsToBlocksWithIndexedNames(
        mappings: List<Triple<DyldCacheMappingAndSlideInfo, ByteProvider, Int>>,
        prefix: String,
        forEachBlock: (MemoryBlock) -> Unit = {},
    ) = mappings
        .mapIndexed { index, (mapping, provider) ->
            try {
                val block = mapMappingAndSlide(mapping, provider, "$prefix $index", null)
                forEachBlock(block)
                return@mapIndexed block
            } catch (_: Exception) {
                return@mapIndexed null
            }
        }.filterNotNull()

    fun mapStubOptimizations() {
        if (!cacheHelper.cacheHasStubOptimizations) return
        val mappedBlocks =
            // TODO: Determine if we can filter these based on if they are relevant for the dylib to be loaded.
            mapMappingsToBlocksWithIndexedNames(cacheHelper.stubOptimizationMappings, STUBS_PROGRAM_TREE_NAME)
        if (mappedBlocks.isNotEmpty()) {
            program.listing.defaultRootModule
                .createModule(STUBS_PROGRAM_TREE_NAME)
                .apply { mappedBlocks.forEach { reparent(it.name, program.listing.defaultRootModule) } }
        }
    }

    fun mapLibObjCOptimizations() {
        val header = cacheHelper.findMachHeaderForImage("/usr/lib/libobjc.A.dylib") ?: return
        val section =
            header
                .allSegments
                .firstOrNull { it.segmentName == "__TEXT" }
                ?.sections
                ?.firstOrNull { it.sectionName == "__objc_opt_ro" }
                ?: return
        val (_, provider) =
            cacheHelper.findRelevantMapping(section.address) ?: return

        // TODO: The following two values are defined mostly for explanatory benefit. Confirm if we should just
        //  simplify the process and combine some of these math operations instead.

        // The header should always be at the beginning of the `__objc_opt_ro` section.
        val objCOptimizationsHeaderStartAddress = section.address

        // The offset field lives after two `uint32_t`'s (version and flags) and one `int32_t` (`selopt_offset`).
        val readonlyOffsetFieldAddress =
            objCOptimizationsHeaderStartAddress + (UInt.SIZE_BYTES * 2) + Int.SIZE_BYTES

        // Read the offset from the header
        val roOffsetFromHeader: Int = cacheHelper.readMappedNumber(readonlyOffsetFieldAddress)
        var roOffset = section.address + roOffsetFromHeader

        // Map the relevant mapping into the program
        // TODO: Confirm that the mapping that contains [roOffset] is the *only* mapping we should care about.
        val (roMapping, roProvider) =
            cacheHelper.findRelevantMapping(roOffset) ?: return
        mapMappingAndSlide(roMapping, roProvider, READ_ONLY_DATA_PROGRAM_TREE_NAME, null)
    }

    fun mapReadOnlyData(): List<MemoryBlock> {
        val mappedBlocks =
            mapMappingsToBlocksWithIndexedNames(cacheHelper.readOnlyMappings, READ_ONLY_DATA_PROGRAM_TREE_NAME) { roBlock ->
                roBlock.isRead = true
                roBlock.isWrite = false
                roBlock.isExecute = false
            }
        if (mappedBlocks.isNotEmpty()) {
            program.listing.defaultRootModule
                .createModule(READ_ONLY_DATA_PROGRAM_TREE_NAME)
                .apply { mappedBlocks.forEach { reparent(it.name, program.listing.defaultRootModule) } }
        }
        return mappedBlocks
    }

    fun mapMapping(
        mapping: DyldCacheMappingInfo,
        provider: ByteProvider,
        blockName: String,
        monitor: TaskMonitor?,
    ): MemoryBlock {
        val baseAddress = program.addressFactory.defaultAddressSpace.getAddress(mapping.address)
        val block =
            program.memory.createInitializedBlock(
                blockName,
                baseAddress,
                mapping.size,
                (0).toByte(),
                monitor,
                false,
            )
        val bytes = provider.readBytes(mapping.fileOffset, mapping.size)
        block.putBytes(baseAddress, bytes)
        return block
    }

    fun mapMappingAndSlide(
        mapping: DyldCacheMappingAndSlideInfo,
        provider: ByteProvider,
        blockName: String,
        monitor: TaskMonitor?,
    ): MemoryBlock {
        val baseAddress = program.addressFactory.defaultAddressSpace.getAddress(mapping.address)
        val block =
            program.memory.createInitializedBlock(
                blockName,
                baseAddress,
                mapping.size,
                (0).toByte(),
                monitor,
                false,
            )
        val bytes = provider.readBytes(mapping.fileOffset, mapping.size)
        block.putBytes(baseAddress, bytes)
        return block
    }
}
