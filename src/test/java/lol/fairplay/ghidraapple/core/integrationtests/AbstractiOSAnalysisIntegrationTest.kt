package lol.fairplay.ghidraapple.core.integrationtests

import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.framework.cmd.Command
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadedIntegrationTest
import lol.fairplay.ghidraapple.analysis.passes.dynamicdispatch.IntraProceduralImplementationAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCMethodAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCStructureAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCTypeInjectorAnalyzer
import lol.fairplay.ghidraapple.db.DataBaseLayer
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Base class for iOS analysis integration tests
 *
 * Each program is split into its own test file so we can easily run them all in parallel
 */
abstract class AbstractiOSAnalysisIntegrationTest : AbstractGhidraHeadedIntegrationTest() {
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
        options.setBoolean(IntraProceduralImplementationAnalyzer.NAME, true)
        options.setBoolean(OCTypeInjectorAnalyzer.NAME, true)
        options.setBoolean(OCStructureAnalyzer.NAME, true)

        autoAnalyzer.reAnalyzeAll(null)
        val cmd: Command<Program> = AnalysisBackgroundCommand(autoAnalyzer, false)
        cmd.applyTo(program)

        return program
    }

    protected fun testTypeBound(
        program: Program,
        vararg expectedResults: Pair<Long, String>,
    ) {
        val typeBoundMap = DataBaseLayer(program).getAllTypeBounds()?.mapValues { (k, v) -> v.name }
        assertNotNull(typeBoundMap, "Type bound data not found")
        assert(typeBoundMap.isNotEmpty())

        expectedResults.forEach { (t, u) ->
            val address = program.addressFactory.defaultAddressSpace.getAddress(t)
            val typeBound = typeBoundMap[address]
            assertNotNull(typeBound, "No type bound found for address $address")
            assertEquals(u, typeBound)
        }
    }

    protected fun testStaticReceivers(
        program: Program,
        vararg expectedResults: Pair<Long, String>,
    ) {
        val db = DataBaseLayer(program)

        expectedResults.forEach { (callsite, className) ->
            val address = program.addressFactory.defaultAddressSpace.getAddress(callsite)
            assertEquals(
                className,
                db.getStaticReceiverClassAtCallsite(address)?.name?.removePrefix("_OBJC_CLASS_\$_"),
                "Wrong static receiver at $address",
            )
        }
    }

    /**
     * Test if the selector for a msgSend call is correct
     */
    protected fun testSelectors(
        program: Program,
        vararg results: Pair<Long, String>,
    ) {
        val db = DataBaseLayer(program)

        results.forEach { (callsite, selector) ->
            val address = program.addressFactory.defaultAddressSpace.getAddress(callsite)
            assertEquals(
                selector,
                db.getSelectorAtCallsite(address),
                "Wrong selector at $address",
            )
        }
    }

    protected fun testIntraAllocs(
        program: Program,
        vararg results: Pair<Long, String>,
    ) {
        val db = DataBaseLayer(program)

        results.forEach { (callsite, expectedClassName) ->
            val address = program.addressFactory.defaultAddressSpace.getAddress(callsite)
            val className = db.getAllocedReceiverClassnameAtCallsite(address)!!
            assertEquals(
                expectedClassName,
                className,
                "Wrong alloced receiver at $address",
            )
        }
    }
}
