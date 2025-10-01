import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.framework.cmd.Command
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.DataTypeSymbol
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.symbol.Symbol
import ghidra.test.AbstractGhidraHeadedIntegrationTest
import lol.fairplay.ghidraapple.analysis.objectivec.GhidraTypeBuilder.Companion.OBJC_CLASS_CATEGORY
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.ApplyAllocTypeOverrideCommand
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCMethodAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCStructureAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCTypeInjectorAnalyzer
import lol.fairplay.ghidraapple.analysis.passes.selectortrampoline.SelectorTrampolineAnalyzer
import org.junit.jupiter.api.Test
import resources.ResourceManager
import java.io.File
import kotlin.test.Ignore
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/*
Type lattice of Mach-O binary "TestApplicationTypeInference":

        ID
        |
     ___|______________________
    |             |            |
Accommodation    Human       Animal
    |             |            |
    |             |       _____|________________
    |             |      |           |         |
    |             |     Cat         Dog       Horse
    |             |      |           |         |
    |_____________|______|___________|_________|
                      |
                      |
                    Bottom

The binary is an objc release build with Xcode (Clang) for iOS (arm64) without optimization.
 */

class ObjcAllocationInitializationTest : AbstractGhidraHeadedIntegrationTest() {
    /**
     * Sets up the program for testing function overrides at allocation and initialization sites.
     *
     * @param file the binary file
     * @return the Ghidra program
     */
    private fun setupProgramForBinary(file: File): Program {
        val ghidraProject = GhidraProject.createProject("/tmp", "${this::class.simpleName}_${file.name}", true)
        val program = ghidraProject.importProgram(file)
        val autoAnalyzer = AutoAnalysisManager.getAnalysisManager(program)
        val options = program.getOptions(Program.ANALYSIS_PROPERTIES)

        options.setBoolean(OCMethodAnalyzer.NAME, true)
        options.setBoolean(OCStructureAnalyzer.NAME, true)
        options.setBoolean(OCTypeInjectorAnalyzer.NAME, true)

        autoAnalyzer.reAnalyzeAll(null)
        val cmd: Command<Program> = AnalysisBackgroundCommand(autoAnalyzer, false)
        cmd.applyTo(program)

        return program
    }

    /**
     * Returns the function by its name from the symbol table. Asserts that the function name is unique.
     *
     * @param program the current Ghidra program
     * @param functionName the name of the function
     * @return the Ghidra function object
     */
    private fun getFunctionByName(
        program: Program,
        functionName: String,
    ): Function {
        val functionAddress =
            program.symbolTable
                .getGlobalSymbols(functionName)
                .single()
                .address
        val function = program.functionManager.getFunctionAt(functionAddress)
        assertNotNull(functionAddress, "Function not found in program")

        return function
    }

    /**
     * Returns the function signature override at a call site as Ghdira FunctionDefinition object to access
     * its type information.
     *
     * @param program the current Ghidra program
     * @param callSite the address of the expected signature override
     * @return the function signature as Ghidra FunctionDefinition object
     */
    private fun getSignatureOverrideAtCallSite(
        program: Program,
        callSite: Address,
    ): FunctionDefinition {
        // get the primary symbol at the call site address
        val primarySymbol: Symbol? = program.symbolTable.getSymbols(callSite).singleOrNull { it.isPrimary }
        // if a primary symbol is not found, there was no signature override
        assertNotNull(primarySymbol, "Expected primary symbol was not found")

        // check for function signature override
        val dataTypeSymbolOverride: DataTypeSymbol? = HighFunctionDBUtil.readOverride(primarySymbol)
        assertNotNull(dataTypeSymbolOverride, "Expected function signature override was not found")

        return dataTypeSymbolOverride.dataType as FunctionDefinition
    }

    /**
     * This function asserts that the return type of a present function signature override at a *unique* call site
     * inside an encapsulating function is of an expected type and especially a pointer. It assumes that there is a
     * unique call site to [functionAddress] inside the function corresponding to [encapsulatingFunctionName]. The
     * parameter [functionAddress] can also be derived from a symbol address, e.g. when looking for references to a stub.
     *
     * @param program the current Ghidra program
     * @param functionAddress the address of the referenced function
     * @param encapsulatingFunctionName the name of the encapsulating function (hardcoded in the test binary)
     * @param returnTypeExpectedPointerName the expected name of the return type of the signature override
     */
    private fun assertUniqueFunctionCallSiteReturnType(
        program: Program,
        functionAddress: Address,
        encapsulatingFunctionName: String,
        returnTypeExpectedPointerName: String,
    ) {
        // get encapsulating function
        val encapsulatingFunction = getFunctionByName(program, encapsulatingFunctionName)

        // check if there is a unique reference to function in the encapsulating function body (true by test design)
        val functionReferences = program.referenceManager.getReferencesTo(functionAddress)
        val listOfReferencesInTestFunction =
            functionReferences.map { it.fromAddress }.filter<Address>(encapsulatingFunction.body::contains)
        assertEquals(1, listOfReferencesInTestFunction.size)

        // get the return type (always a pointer to a class by test design) of the signature at function call site and check for the expected name
        val functionCallSite = listOfReferencesInTestFunction.single()
        val signature: FunctionDefinition = getSignatureOverrideAtCallSite(program, functionCallSite)
        val returnType = signature.returnType as Pointer
        assertEquals(returnType.name, returnTypeExpectedPointerName)
    }

    /**
     * Tests the signature overrides of allocation sites by calls to _objc_alloc for the classes in the test binary.
     */
    @Test
    fun testAllocationSites() {
        // initialize and set up program
        val program = setupProgramForBinary(ResourceManager.getResourceFile("TestApplicationTypeInference"))

        // get _objc_alloc
        val objcAlloc = getFunctionByName(program, "_objc_alloc")

        val testFunctionNamesAndExpectedReturnTypes: Map<String, String> =
            mapOf(
                "_testAllocationSiteHuman" to "Human *",
                "_testAllocationSiteAnimal" to "Animal *",
                "_testAllocationSiteCat" to "Cat *",
                "_testAllocationSiteDog" to "Dog *",
                "_testAllocationSiteHorse" to "Horse *",
                "_testAllocationSiteAccommodation" to "Accommodation *",
            )

        testFunctionNamesAndExpectedReturnTypes.forEach {
            assertUniqueFunctionCallSiteReturnType(
                program,
                objcAlloc.entryPoint,
                it.key,
                it.value,
            )
        }
    }

    /**
     * Tests the signature overrides of allocation and initialization sites by calls to _objc_alloc_init for the classes in the test binary.
     */
    @Test
    fun testAllocInitSites() {
        // initialize and set up program
        val program = setupProgramForBinary(ResourceManager.getResourceFile("TestApplicationTypeInference"))

        // get _objc_alloc_init
        val objcAllocInit = getFunctionByName(program, "_objc_alloc_init")

        val testFunctionNamesAndExpectedReturnTypes: Map<String, String> =
            mapOf(
                "_testAllocInitSiteHuman" to "Human *",
                "_testAllocInitSiteAnimal" to "Animal *",
                "_testAllocInitSiteCat" to "Cat *",
                "_testAllocInitSiteDog" to "Dog *",
                "_testAllocInitSiteHorse" to "Horse *",
                "_testAllocInitSiteAccommodation" to "Accommodation *",
            )

        testFunctionNamesAndExpectedReturnTypes.forEach {
            assertUniqueFunctionCallSiteReturnType(program, objcAllocInit.entryPoint, it.key, it.value)
        }
    }

    /**
     *     Tests the signature overrides of separated allocation and initialization sites, where they are considered to be separated in the sense that
     *     they are translated to a single call to _objc_alloc and a call to a stub::init afterward, for the classes in the test binary.
     */
    @Ignore("Init type override not implemented yet.")
    @Test
    fun testAllocInitSeparatedSites() {
        // initialize and set up program
        val program = setupProgramForBinary(ResourceManager.getResourceFile("TestApplicationTypeInference"))

        // get _objc_alloc
        val objcAlloc = getFunctionByName(program, "_objc_alloc")

        // get init stub symbol
        val stubNameSpace =
            program.symbolTable.getNamespace(SelectorTrampolineAnalyzer.STUB_NAMESPACE_NAME, program.globalNamespace)
        val init = program.symbolTable.getSymbols("init", stubNameSpace).single()

        val testFunctionNamesAndExpectedReturnTypes: Map<String, String> =
            mapOf(
                "_testAllocInitSeparatedSitesHuman" to "Human *",
                "_testAllocInitSeparatedSitesAnimal" to "Animal *",
                "_testAllocInitSeparatedSitesCat" to "Cat *",
                "_testAllocInitSeparatedSitesDog" to "Dog *",
                "_testAllocInitSeparatedSitesHorse" to "Horse *",
                "_testAllocInitSeparatedSitesAccommodation" to "Accommodation *",
            )

        testFunctionNamesAndExpectedReturnTypes.forEach {
            assertUniqueFunctionCallSiteReturnType(
                program,
                objcAlloc.entryPoint,
                it.key,
                it.value,
            )
        }
        testFunctionNamesAndExpectedReturnTypes.forEach {
            assertUniqueFunctionCallSiteReturnType(
                program,
                init.address,
                it.key,
                it.value,
            )
        }
    }

    private fun buildAllocHumanProgram(): ProgramBuilder {
        val builder = ProgramBuilder("allocHumanTest", ProgramBuilder._AARCH64)
        builder.setBytes(
            "0x100008c34",
            listOf(
                "ff 83 00 d1",
                "fd 7b 01 a9",
                "fd 43 00 91",
                "48 00 00 b0",
                "00 bd 42 f9",
                "2b 02 00 94",
                "e8 03 00 aa",
                "e0 23 00 91",
                "e8 07 00 f9",
                "01 00 80 d2",
                "2f 02 00 94",
                "fd 7b 41 a9",
                "ff 83 00 91",
                "c0 03 5f d6",
            ).joinToString(" "),
            // Don't disassemble because this would trigger instruction analyzers already
            false,
        )
        builder.createEmptyFunction(
            "_objc_alloc",
            "0x1000094f4",
            1,
            DataType.DEFAULT,
            // This is intentionally created without a parameter, because the analyzer should handle
            // cases where the alloc function is not properly typed yet
        )
        builder.createEmptyFunction(
            "_testAllocationSiteHuman",
            "0x100008c34",
            (0x100008c6c - 0x100008c34).toInt(),
            DataType.DEFAULT,
        )
        builder.createEmptyFunction("_objc_storeStrong", "0x100009518", 1, DataType.DEFAULT)
        builder.createLabel("0x100011778", "_OBJC_CLASS_\$_Human")
        builder.setBytes("0x100011578", "78 17 01 00 01 00 00 00")

        /** TODO: The category is currently a hardcoded string
         * Once we have the central "Service" or "Pivot" class for Objective-C data it should be used to add the class
         * The [OCTypeInjectorAnalyzer] relies on the class being present in the program's data type manager
         */
        builder.addDataType(
            StructureDataType(OBJC_CLASS_CATEGORY, "Human", 8),
        )
        return builder
    }

    /**
     * Tests the [OCTypeInjectorAnalyzer] on a minimal program, with manual set up of the pre-requisite info
     *
     * Hard to say if this is a "unit" or an "integration" test, but it's a good minimal test for the analyzer
     */
    @Test
    fun testTypeInjectionAnalyzer() {
        val builder = buildAllocHumanProgram()
        val program = builder.program
        program.withTransaction<Exception>("first analysis") {
            val autoAnalyzer = AutoAnalysisManager.getAnalysisManager(program)
            val options = program.getOptions(Program.ANALYSIS_PROPERTIES)
            options.setBoolean(OCTypeInjectorAnalyzer.NAME, true)
            autoAnalyzer.reAnalyzeAll(null)
            val cmd: Command<Program> = AnalysisBackgroundCommand(autoAnalyzer, false)
            cmd.applyTo(program)
        }

//        env.launchDefaultTool(program)
        val signature: FunctionDefinition = getSignatureOverrideAtCallSite(program, builder.addr(0x100008c48))
        val returnType = signature.returnType as Pointer
        assertEquals("Human *", returnType.name)
    }

    /**
     * Tests the [ApplyAllocTypeOverrideCommand] on a minimal program, with manual set up of the pre-requisite info
     */
    @Test
    fun testTypeInjectionMinimalUnit() {
        val builder = buildAllocHumanProgram()
        val program = builder.program

        val dt = program.dataTypeManager.getPointer(program.dataTypeManager.getDataType(OBJC_CLASS_CATEGORY, "Human"))
        program.withTransaction<Exception>("Apply override") {
            ApplyAllocTypeOverrideCommand(builder.addr("100008c48"), dt).applyTo(program)
        }
//            this.launchDefaultTool(program)
        val signature: FunctionDefinition = getSignatureOverrideAtCallSite(program, builder.addr(0x100008c48))
        val returnType = signature.returnType as Pointer
        assertEquals("Human *", returnType.name)
    }
}
