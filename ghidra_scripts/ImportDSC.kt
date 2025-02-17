import ghidra.app.script.GhidraScript
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.formats.gfilesystem.FSRL
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.formats.gfilesystem.GFile
import ghidra.program.model.listing.Library
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.ExternalManager
import java.io.File

private val ExternalManager.externalLibraries: List<Library>
    get() = this.externalLibraryNames.map { this.getExternalLibrary(it) }.toList()

class ImportDSC : GhidraScript() {
    override fun run() {
        println("Running ImportDSC script")
        val filesystemImage: File = askFile("Choose Filesystem Container", "Select")
        // Should be something like 21G93__iPhone16,2
        val iPhoneIdentifier = filesystemImage.parentFile.name
        println("Importing filesystem image for $iPhoneIdentifier")
        val fsrl = FSRL.fromString("file://" + filesystemImage.getAbsolutePath())
        val fileSystemService = FileSystemService.getInstance()
//        fileSystemService.allFilesystemNames.forEach { println(it) }
        val fs = fileSystemService.openFileSystemContainer(fsrl, monitor)
        // Iterate over all files not in "/DYLD_DATA" nor "/STUBS/"
        // should only be "/usr" and "/System"
        println("Collecting files")
        val allFiles = FileTreeWalker(fs.rootDir).files.filterNot { it.path.startsWith("/STUBS") || it.path.startsWith("/DYLD_DATA") }
        println("Importing ${allFiles.size} files")
        val messageLog = MessageLog()
        val total = allFiles.size
        allFiles.forEachIndexed { index, it ->
            val path = "/" + iPhoneIdentifier + it.parentFile.path
            println("Processing ${it.path}")
            if (state.project.projectData.getFile('/' + iPhoneIdentifier + it.path) != null) {
                println("Already imported $path")
                return@forEachIndexed
            }
            println("Storing to $path")
            val exampleResult =
                AutoImporter.importByUsingBestGuess(
                    it.fsrl,
                    state.project,
                    path,
                    this,
                    messageLog,
                    monitor,
                )
            exampleResult.save(state.project, this, messageLog, monitor)
            val domainFile = exampleResult.primaryDomainObject.domainFile
            val program = exampleResult.primaryDomainObject

            fixUpReferences(program, iPhoneIdentifier)
            domainFile.save(monitor)
            if (domainFile.canAddToRepository()) {
                domainFile.addToVersionControl("Imported $iPhoneIdentifier DSC", true, monitor)
            }
            exampleResult.release(this)
            println("Processed $index/$total")
        }
    }

    fun fixUpReferences(
        program: Program,
        projectPrefix: String,
    ) {
        program.withTransaction<Exception>("Set external programs") {
            val externalManager = program.externalManager

            val projectPrefix =
                if (!projectPrefix.startsWith('/')) {
                    '/' + projectPrefix
                } else {
                    projectPrefix
                }
            externalManager.externalLibraryNames
                .filter { it.startsWith('/') }
                .forEach {
                    externalManager.setExternalPath(it, projectPrefix + it, false)
                }
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
