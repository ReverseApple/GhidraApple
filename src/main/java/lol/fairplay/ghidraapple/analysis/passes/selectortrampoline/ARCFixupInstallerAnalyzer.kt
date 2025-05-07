package lol.fairplay.ghidraapple.analysis.passes.selectortrampoline

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.bin.format.objc2.ObjectiveC2_Constants
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.SpecExtension
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import resources.ResourceManager

class ARCFixupInstallerAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {
    companion object {
        private const val NAME = "Objective-C Call Fixups"
        private const val DESCRIPTION =
            "Adds callfixup for ObjC runtime methods"
        private const val NOP_PCODE = """
            
        """
        const val OBJC_WO_SEL_CC = "__objc_wo_selector"
    }

    init {
        setDefaultEnablement(true)
        priority = AnalysisPriority.FORMAT_ANALYSIS
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program?): Boolean = ObjectiveC2_Constants.isObjectiveC2(program)

    private fun createCallFixupXML(
        name: String,
        code: String,
        vararg targets: String,
    ): String =
        """
        <callfixup name="$name">
          ${targets.joinToString("\n") { "<target name=\"$it\"/>" }}
          <pcode>
            <body><![CDATA[
                    $code
             ]]></body>
          </pcode>
        </callfixup>
        """.trimIndent()

    override fun added(
        program: Program?,
        set: AddressSetView?,
        monitor: TaskMonitor?,
        log: MessageLog?,
    ): Boolean {
        val specExtension = SpecExtension(program)

        val retainRegisters = (0..28).map { "_objc_retain_x$it" }
        val retainSpec =
            createCallFixupXML(
                "_objc_retain",
                "x0 = x0;",
                "_objc_retain",
                "_objc_retainAutoreleasedReturnValue",
                "_objc_retainAutoreleaseReturnValue",
                "_objc_autoreleaseReturnValue",
                "_objc_retainAutorelease",
                "_objc_autorelease",
                "_objc_claimAutoreleasedReturnValue",
                "___chkstk_darwin",
                "_objc_opt_self",
                "_objc_unsafeClaimAutoreleasedReturnValue",
                "_objc_retainBlock",
                *retainRegisters.toTypedArray(),
            )

        val releaseRegisters = (0..28).map { "_objc_release_x$it" }
        val releaseSpec =
            createCallFixupXML(
                "objc_release",
                "x0 = 0;",
                "_objc_release",
                *releaseRegisters.toTypedArray(),
            )

        val storeStrongSpec =
            createCallFixupXML(
                "_objc_storeStrong",
                "*x0 = x1;",
                "_objc_storeStrong",
                "_objc_storeWeak",
            )

        val loadSpec =
            createCallFixupXML(
                "_objc_loadWeakRetained",
                "x0 = *x0;",
                "_objc_loadWeakRetained",
                "_objc_loadWeak",
            )

        val getPropertySpec =
            createCallFixupXML(
                "_objc_getProperty",
                "x0 = *(x0 + x2);",
                "_objc_getProperty",
            )

        val setPropertySpec =
            createCallFixupXML(
                "_objc_setProperty",
                "*(x0 + x3) = x2;",
                "_objc_setProperty",
                "_objc_setProperty_atomic",
                "_objc_setProperty_atomic_copy",
                "_objc_setProperty_nonatomic",
                "_objc_setProperty_nonatomic_copy",
            )

        val specs =
            listOf(
                retainSpec,
                releaseSpec,
                storeStrongSpec,
                loadSpec,
                getPropertySpec,
                setPropertySpec,
            )
        specs.forEach {
            specExtension.addReplaceCompilerSpecExtension(it, monitor)
        }

        val xmlSpec = ResourceManager.getResourceAsStream("objc_skip_x1_cc.cspec").bufferedReader().readText()
        specExtension.addReplaceCompilerSpecExtension(xmlSpec, monitor)
        return true
    }
}
