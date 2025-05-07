package lol.fairplay.ghidraapple.core.typeinference

import lol.fairplay.ghidraapple.core.integrationtests.AbstractiOSAnalysisIntegrationTest
import org.junit.jupiter.api.Test

class IntraProcAnalyzerTest : AbstractiOSAnalysisIntegrationTest() {
    /**
     *                              **************************************************************
     *                              *                          FUNCTION                          *
     *                              **************************************************************
     *                              void __cdecl invoke_10007d678(Block_layout_100079434 * b
     *              void              <VOID>         <RETURN>
     *              Block_layout_1    x0:8           block
     *                              invoke_10007d678                                XREF[2]:     FUN_1000778ac:10007945c(*),
     *                                                                                           10017f7a5(*)
     *           __text:10007d678 c8 07 00 d0     adrp       x8,0x100177000
     *           __text:10007d67c 08 a1 39 91     add        x8,x8,#0xe68
     *           __text:10007d680 08 01 40 f9     ldr        x8,[x8]=>DAT_100177e68
     *           __text:10007d684 02 24 42 a9     ldp        x2,x9,[x0, #block->field5_0x20]
     *           __text:10007d688 23 bd 40 b9     ldr        w3,[x9, #0xbc]
     *           __text:10007d68c e0 03 08 aa     mov        block,x8
     *           __text:10007d690 2c ea 01 14     b          stub::interfaceAddedWithName:role:               ID interfaceAddedWithName:role:(
     *                              -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
     *
     * ```C
     * void invoke_10007d678(Block_layout_100079434 *block)
     *
     * {
     *   SEL in_x1;
     *
     *   stub::interfaceAddedWithName:role:
     *             (DAT_100177e68,in_x1,*(undefined8 *)&block->field_0x20,
     *              (ulong)*(uint *)(*(long *)&block->field_0x28 + 0xbc));
     *   return;
     * }
     * ```
     *
     *
     *
     */
    @Test
    fun testDataReceiver() {
    }
}
