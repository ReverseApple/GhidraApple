package lol.fairplay.ghidraapple.analysis.passes.strings

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SmallStringLiteralAnalyzerTest {
    /** The 16 raw bytes of a small `_StringObject`: content, zero padding, discriminator|count. */
    private fun stringObject(
        content: String,
        discriminator: Int = 0xe0,
    ): ByteArray {
        val bytes = ByteArray(16)
        content.toByteArray(Charsets.US_ASCII).copyInto(bytes)
        bytes[15] = (discriminator or content.length).toByte()
        return bytes
    }

    @Test
    fun `decodes the word pairs emitted for arm64 and x86-64`() {
        // Both targets build the same two words; these are taken from a compiled sample.
        assertEquals(
            "Hi",
            SmallStringLiteralAnalyzer.decodeSmallString(0x6948L, -0x1e00000000000000L),
        )
        assertEquals(
            "FIe0mUHX",
            SmallStringLiteralAnalyzer.decodeSmallString(0x5848556d30654946L, -0x1800000000000000L),
        )
        // 14 characters, so the discriminator word carries content of its own.
        assertEquals(
            "slJalCsOaL9w70",
            SmallStringLiteralAnalyzer.decodeSmallString(0x4f73436c614a6c73L, -0x11ffcfc888c6b39fL),
        )
        assertEquals(
            "Hello, World!!!",
            SmallStringLiteralAnalyzer.decodeSmallString(0x57202c6f6c6c6548L, -0x10dedede9b938d91L),
        )
    }

    @Test
    fun `rejects word pairs that are not small strings`() {
        // A large string: isSmall clear, the second word is a tagged pointer.
        assertNull(SmallStringLiteralAnalyzer.decodeSmallString(0x10L, -0x7ffffffffffff000L))
        // Two unrelated immediates that happen to be stored 8 bytes apart.
        assertNull(SmallStringLiteralAnalyzer.decodeSmallString(0x1L, 0x2L))
    }

    @Test
    fun `rejects byte layouts that fail any field check`() {
        assertNull(SmallStringLiteralAnalyzer.decodeSmallString(stringObject("")))
        // isForeign set alongside isSmall is not an inline string.
        assertNull(SmallStringLiteralAnalyzer.decodeSmallString(stringObject("Hi", discriminator = 0xf0)))
        // Content past the declared count must be zero padding.
        assertNull(
            SmallStringLiteralAnalyzer.decodeSmallString(
                stringObject("Hi").also { it[4] = 'x'.code.toByte() },
            ),
        )
        // Non-printable content.
        assertNull(
            SmallStringLiteralAnalyzer.decodeSmallString(
                stringObject("Hi").also { it[1] = 0x01 },
            ),
        )
    }
}
