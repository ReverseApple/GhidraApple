package lol.fairplay.ghidraapple.core.te

import ghidra.test.AbstractGhidraHeadedIntegrationTest
import ghidra.test.TestEnv
import lol.fairplay.ghidraapple.te.TEParser
import org.junit.jupiter.api.Test
import java.io.File

class TETests : AbstractGhidraHeadedIntegrationTest() {
    fun parseTEOutput(
        outputPath: String,
        dtmPath: String,
    ) {
        val env = TestEnv()
        val dtmFile = File(dtmPath)
        val parser = TEParser(env.tool, dtmFile)
        val teOutputFile = File(outputPath)
        parser.parseEmittedTypes(teOutputFile.readLines())
    }

    @Test
    fun testTEOutputParser() {
        // TODO: Call [parseTEOutput] on some output files.
    }
}
