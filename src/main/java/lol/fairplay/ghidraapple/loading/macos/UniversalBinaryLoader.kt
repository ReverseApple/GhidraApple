package lol.fairplay.ghidraapple.loading.macos

import ghidra.app.util.Option
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.Loaded
import ghidra.app.util.opinion.MachoLoader;
import ghidra.file.formats.ubi.UniversalBinaryFileSystem
import ghidra.formats.gfilesystem.annotations.FileSystemInfo
import ghidra.framework.model.Project
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import kotlin.reflect.full.findAnnotation

class UniversalBinaryLoader : MachoLoader() {

    override fun getPreferredFileName(byteProvider: ByteProvider): String {
        val original = super.getPreferredFileName(byteProvider)
        val ubType = UniversalBinaryFileSystem::class.findAnnotation<FileSystemInfo>()?.type ?: "universalbinary"
        // If this isn't a universal binary then just return the original file name.
        if (!byteProvider.fsrl.toStringPart().startsWith("$ubType://")) return original;

        // The fsrl is two-fold: the path to the binary, and a path within the binary. We take the former
        // and extract the name (which will be the last path component, the binary name).
        var binaryName = byteProvider.fsrl.split()[0].name
        return "$binaryName-$original";
    }

    override fun postLoadProgramFixups(
        loadedPrograms: MutableList<Loaded<Program>>?,
        project: Project?,
        options: MutableList<Option>?,
        messageLog: MessageLog?,
        monitor: TaskMonitor?
    ) {
        super.postLoadProgramFixups(loadedPrograms, project, options, messageLog, monitor)
        if (loadedPrograms != null) {
            for (loaded in loadedPrograms) {
                // The actual program is wrapped, so we need to unwrap it.
                val program = loaded.domainObject

                // We rename with the preferred name.
                val renameTransaction = program.startTransaction("rename")
                // This will trigger [getPreferredFileName] above.
                program.name = loaded.name
                program.endTransaction(renameTransaction, true)

                // The programs will still be in folders named after the architecture. We need
                // to move them up to the folder named after the binary.
                val originalFolderPath = loaded.projectFolderPath
                val newFolderPath = originalFolderPath
                    .split("/")
                    // Filter out, potentially, the last empty element (if the path ended in "/").
                    .filter { it != "" }
                    .dropLast(1)
                    .joinToString("/")
                loaded.projectFolderPath = newFolderPath
                project?.projectData?.getFolder(originalFolderPath)?.delete()
            }
        }
    }

}