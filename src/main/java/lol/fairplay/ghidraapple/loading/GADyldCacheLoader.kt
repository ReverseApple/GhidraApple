package lol.fairplay.ghidraapple.loading

import ghidra.app.util.Option
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.DyldCacheExtractLoader
import ghidra.app.util.opinion.LoadSpec
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.filesystems.GADyldCacheFileSystem

class GADyldCacheLoader: DyldCacheExtractLoader() {
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
        log: MessageLog?
    ) {
        super.load(provider, loadSpec, options, program, monitor, log)
        if (provider == null || program == null) return

        // The executable format is named after the loader. However, Ghidra performs some checks against this name to
        // enable certain analyzers (so we have to give it a name it expects: the name of the built-in loader).
        program.executableFormat = super.getName()

        val fileSystem = FileSystemService.getInstance().getFilesystem(provider.fsrl.fs, null).filesystem
        if (fileSystem !is GADyldCacheFileSystem) return

        val infoOptions = program.getOptions(Program.PROGRAM_INFO)
        val cachePlatform = fileSystem.platform?.prettyName ?: "unknownOS"
        val cacheVersion = fileSystem.osVersion ?: "?.?.?"
        infoOptions.setString("Dyld Cache Platform", "$cachePlatform $cacheVersion")
    }
}