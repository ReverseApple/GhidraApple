import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.AutoImporter
import ghidra.app.util.importer.MessageLog
import ghidra.base.project.GhidraProject
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.StackReference
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import lol.fairplay.ghidraapple.analysis.passes.blocks.ObjectiveCGlobalBlockAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.blocks.ObjectiveCStackBlockAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCMethodAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCStructureAnalyzer
import org.junit.jupiter.api.Test
import resources.ResourceManager
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AutoAnalysisIntegrationTests : AbstractGhidraHeadlessIntegrationTest() {
    fun setupProgramForBinary(file: File): Program {
        val ghidraProject =
            GhidraProject.createProject("/tmp", "${this::class.simpleName}_${file.name}", true)
        val fileSystemService = FileSystemService.getInstance()
        val fullFSRL =
            fileSystemService.getFullyQualifiedFSRL(
                fileSystemService.getLocalFSRL(file),
                TaskMonitor.DUMMY,
            )

        val program: Program =
            if (fileSystemService.isFileFilesystemContainer(
                    fullFSRL,
                    TaskMonitor.DUMMY,
                )
            ) {
                fileSystemService
                    .openFileSystemContainer(fullFSRL, TaskMonitor.DUMMY)
                    .also {
                        // We don't want to handle any other containers besides universal binaries at this point.
                        if (!it.fsrl.toStringPart().startsWith("universalbinary://")) {
                            assert(false) { "Universal binaries are the only accepted container type." }
                        }
                    }.getListing(null)
                    .map {
                        val results =
                            AutoImporter
                                .importByUsingBestGuess(
                                    it.fsrl,
                                    ghidraProject.project,
                                    it.path,
                                    this,
                                    MessageLog(),
                                    TaskMonitor.DUMMY,
                                )

                        val program = results.primaryDomainObject
                        results.releaseNonPrimary(this)
                        return@map program
                    }
                    // We're only going to support AARCH (ARM) binaries for now.
                    .first { it.name.contains("AARCH") }
            } else {
                ghidraProject.importProgram(file)
            }

        val options = program.getOptions(Program.ANALYSIS_PROPERTIES)
        val disabledAnalyzers: List<String> =
            listOf(
                "Decompiler Switch Analysis",
                "Objective-C 2 Decompiler Message",
            )
        val enabledAnalyzers: List<String> =
            listOf(
                OCMethodAnalyzer.NAME,
                OCStructureAnalyzer.NAME,
                ObjectiveCGlobalBlockAnalyzer.NAME,
                ObjectiveCStackBlockAnalyzer.NAME,
            )
        program.withTransaction<Exception>("analysis") {
            disabledAnalyzers.forEach { options.setBoolean(it, false) }
            enabledAnalyzers.forEach { options.setBoolean(it, true) }
            AutoAnalysisManager
                .getAnalysisManager(program)
                .apply {
                    reAnalyzeAll(null)
                    startAnalysis(TaskMonitor.DUMMY)
                }
        }

        return program
    }

    @Test
    fun testBlockAnalyzers() {
        val program = setupProgramForBinary(File(System.getenv("PATH_TO_BINARY_WITH_BLOCKS")))

        // Ensure the global blocks are typed correctly.
        program.symbolTable.getSymbols("__NSConcreteGlobalBlock").firstOrNull()?.let {
            program.referenceManager.getReferencesTo(it.address).forEach {
                val dataType = program.listing.getDataAt(it.fromAddress).dataType
                assert(BlockLayoutDataType.isDataTypeBlockLayoutType(dataType)) {
                    "Global block at 0x${it.fromAddress} is not typed as a global block. " +
                        "It has the type ${dataType.name}."
                }
            }
        }

        // Ensure the stack blocks are typed correctly.
        program.symbolTable.getSymbols("__NSConcreteStackBlock").firstOrNull()?.let {
            program.referenceManager.getReferencesTo(it.address).forEach { reference ->
                val function =
                    program.listing.getFunctionContaining(reference.fromAddress) ?: return@forEach
                val instruction =
                    program.listing.getInstructionAt(reference.fromAddress) ?: return@forEach
                val referencedStackOffset =
                    instruction.referencesFrom
                        .filterIsInstance<StackReference>()
                        .firstOrNull()
                        ?.stackOffset ?: return@forEach
                val matchingStackVariable =
                    function.stackFrame.stackVariables
                        .firstOrNull { it.stackOffset == referencedStackOffset } ?: return@forEach
                val dataType = matchingStackVariable.dataType
                assert(BlockLayoutDataType.isDataTypeBlockLayoutType(dataType)) {
                    "Instruction at 0x${reference.fromAddress} does not reference a stack block. " +
                        "It references a ${dataType.name}."
                }
            }
        }
    }

    @Test
    fun testLocationTestApp() {
        val program = setupProgramForBinary(ResourceManager.getResourceFile("LocationTestApp"))

        // Check that the methods are set up correctly
        val didUpdateLocationsAddress = program.addressFactory.defaultAddressSpace.getAddress(0x1000082a4)
        val didUpdateLocationsFunc = program.functionManager.getFunctionAt(didUpdateLocationsAddress)
        assertNotNull(didUpdateLocationsFunc, "Function not found")

        val r =
            listOf(
                // TODO: THIS IS A BUG: The first paremeter should be LocationHelper * but it's ID
                "self" to "LocationHelper *",
                "selector" to "SEL",
                "locationManager" to "CLLocationManager *",
                "didUpdateLocations" to "NSArray *",
            )
        didUpdateLocationsFunc.parameters.forEachIndexed { index, param ->
            assertEquals(r[index].first, param.name)
            assertTrue("Parameter ${param.name} has wrong type: ${param.dataType.name}, expected ${r[index].second}") {
                param.dataType.name.startsWith(r[index].second)
            }
        }
    }
}
