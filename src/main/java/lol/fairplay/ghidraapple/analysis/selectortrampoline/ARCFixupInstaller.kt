package lol.fairplay.ghidraapple.analysis.selectortrampoline

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.bin.format.objc2.ObjectiveC2_Constants
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.SpecExtension
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

class ARCFixupInstallerAnalyzer() : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {
    companion object {
        private const val NAME = "Objective-C Call Fixups"
        private const val DESCRIPTION =
            "Adds callfixup for ObjC runtime methods"
        private const val NOP_PCODE = """
            
        """
    }

    init {
        setDefaultEnablement(true)
        priority = AnalysisPriority.FORMAT_ANALYSIS
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program?): Boolean {
        return ObjectiveC2_Constants.isObjectiveC2(program)
    }

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        val specExtension = SpecExtension(program)

        val retainSpec = """
            <callfixup name="_objc_retain">
              <target name="_objc_retain"/>
              <target name="_objc_retainAutoreleasedReturnValue"/>
              <target name="_objc_retainAutoreleaseReturnValue"/>
              <target name="_objc_autoreleaseReturnValue"/>
              <target name="_objc_retainAutorelease"/>
              <target name="_objc_autorelease"/>
              <target name="_objc_claimAutoreleasedReturnValue"/>
              <target name="___chkstk_darwin"/>


              <pcode>
                  <body><![CDATA[
                  x0 = x0;
                 ]]></body>
              </pcode>
            </callfixup>
        """.trimIndent()
        val releaseSpec = """
            <callfixup name="objc_release">
              <target name="_objc_release"/>
              <pcode>
                <body><![CDATA[
                        x0 = 0;
                 ]]></body>
              </pcode>
            </callfixup>
        """.trimIndent()

        val storeStrongSpec = """
            <callfixup name="_objc_storeStrong">
                <target name="_objc_storeStrong"/>
              <pcode>
                <body><![CDATA[
                        *x0 = x1;
                 ]]></body>
              </pcode>
            </callfixup>
        """.trimIndent()

        val loadSpec = """
                        <callfixup name="_objc_loadWeakRetained">
                            <target name="_objc_loadWeakRetained"/>
                          <pcode>
                            <body><![CDATA[
                                    x0 = *x0;
                             ]]></body>
                          </pcode>
                        </callfixup>
            
        """.trimIndent()

        val getPropertySpec = """
                        <callfixup name="_objc_getProperty">
                            <target name="_objc_getProperty"/>
                          <pcode>
                            <body><![CDATA[
                                    x0 = *(x0 + x2);
                             ]]></body>
                          </pcode>
                        </callfixup>
        """.trimIndent()

        val setPropertSpec = """
                                    <callfixup name="_objc_setProperty_atomic">
                                        <target name="_objc_setProperty_atomic"/>
                                      <pcode>
                                        <body><![CDATA[
                                                *(x0 + x3) = x2;
                                         ]]></body>
                                      </pcode>
                                    </callfixup>
        """.trimIndent()



        val specs = listOf(
            retainSpec, releaseSpec, storeStrongSpec, loadSpec, getPropertySpec, setPropertSpec,
        )
        specs.forEach {
            specExtension.addReplaceCompilerSpecExtension(it, monitor)
        }

        return true
    }
}