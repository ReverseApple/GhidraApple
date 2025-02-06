import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.framework.cmd.Command
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
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
        val ghidraProject = GhidraProject.createProject("/tmp", "${this::class.simpleName}_${file.name}", true)
        val program = ghidraProject.importProgram(file)
        val autoAnalyzer = AutoAnalysisManager.getAnalysisManager(program)
        val options = program.getOptions(Program.ANALYSIS_PROPERTIES)
        // Disable "Decompiler Switch Analysis "
        options.setBoolean("Decompiler Switch Analysis", false)
        // Disable Ghidra's Msg Send analysis
        options.setBoolean("Objective-C 2 Decompiler Message", false)

        options.setBoolean(OCMethodAnalyzer.NAME, true)
        options.setBoolean(OCStructureAnalyzer.NAME, true)

        autoAnalyzer.reAnalyzeAll(null)
        val cmd: Command<Program> = AnalysisBackgroundCommand(autoAnalyzer, false)
        cmd.applyTo(program)

        return program
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
