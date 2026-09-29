package lol.fairplay.ghidraapple.loading

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.opinion.Loaded
import ghidra.app.util.opinion.Loader
import ghidra.app.util.opinion.MachoLoader
import ghidra.program.model.listing.Program

class UniversalBinaryLoader : MachoLoader() {
    override fun getPreferredFileName(byteProvider: ByteProvider): String {
        val original = super.getPreferredFileName(byteProvider)
        val ubType = "universalbinary"
        // If this isn't a universal binary then just return the original file name.
        if (!byteProvider.fsrl.toStringPart().startsWith("$ubType://")) return original

        // The fsrl is two-fold: the path to the binary, and a path within the binary. We take the former
        // and extract the name (which will be the last path component, the binary name).
        val binaryName = byteProvider.fsrl.split()[0].name
        // We prefix with the binary name as the original name is just the architecture and CPU.
        return "$binaryName-$original"
    }

    override fun postLoadProgramFixups(
        loadedPrograms: MutableList<Loaded<Program>>,
        settings: Loader.ImporterSettings,
    ) {
        super.postLoadProgramFixups(loadedPrograms, settings)

        for (loaded in loadedPrograms) {
            // The actual program is wrapped, so we need to unwrap it.
            val program = loaded.getDomainObject(this)

            // This will trigger [getPreferredFileName] above.
            val preferredName = loaded.name

            // If the preferred name is the same as the given name, this probably wasn't
            // part of a universal binary. Thus, we skip any operations.
            if (program.name == preferredName) continue

            // Otherwise, we rename with the preferred name.
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
            loaded.project.projectData?.getFolder(originalFolderPath)?.delete()
        }
    }
}
