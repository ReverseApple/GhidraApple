import ghidra.app.script.GhidraScript
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.formats.gfilesystem.FSRL
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.formats.gfilesystem.GFile
import java.io.File

class ImportDSC : GhidraScript() {
    override fun run() {
        val filesystemImage: File = askFile("Choose Filesystem Container", "Select")
        val fsrl = FSRL.fromString("file://" + filesystemImage.getAbsolutePath())
        val fileSystemService = FileSystemService.getInstance()
//        fileSystemService.allFilesystemNames.forEach { println(it) }
        val fs = fileSystemService.openFileSystemContainer(fsrl, monitor)
        // Iterate over all files not in "/DYLD_DATA" nor "/STUBS/"
        // should only be "/usr" and "/System"
        val allFiles = FileTreeWalker(fs.rootDir).files.filterNot { it.path.startsWith("/STUBS") || it.path.startsWith("/DYLD_DATA") }
        val messageLog = MessageLog()

        allFiles.take(20).forEach {
            val exampleResult =
                AutoImporter.importByUsingBestGuess(
                    it.fsrl,
                    state.project,
                    it.path,
                    this,
                    messageLog,
                    monitor,
                )
            exampleResult.save(state.project, this, messageLog, monitor)
            println(exampleResult.primaryDomainObject.name)
        }
    }
}

class FileTreeWalker(
    root: GFile,
) {
    val files: MutableList<GFile> = mutableListOf()

    init {
        getRecursiveFiles(root)
    }

    private fun getRecursiveFiles(gFile: GFile) {
        if (gFile.isDirectory) {
            gFile.listing.forEach { getRecursiveFiles(it) }
        } else {
            files.add(gFile)
        }
    }
}
