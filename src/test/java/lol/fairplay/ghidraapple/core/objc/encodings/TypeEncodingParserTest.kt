package lol.fairplay.ghidraapple.core.objc.encodings

import kotlin.test.Test

class TypeEncodingParserTest {

    @Test
    fun test_Parser() {
//        val example = "{Person=[50c]idf{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}]}"
//        val example = "{Employee=#if@{?=dd}(?=if)@^?@?}"
//        val example = "{?=\"\"(?=\"\"{?=\"red\"C\"green\"C\"blue\"C\"alpha\"C}\"channel\"[4C]\"value\"I)}"
        val example = "{z_stream_s=\"next_in\"*\"avail_in\"I\"total_in\"Q\"next_out\"*\"avail_out\"I\"total_out\"Q\"msg\"*\"state\"^{internal_state}\"zalloc\"^?\"zfree\"^?\"opaque\"^v\"data_type\"i\"adler\"Q\"reserved\"Q}"
//        val example = "{Person=[50c]b7b1df{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}](?=[50c][15c][30c])i}"
        val lexer = EncodingLexer(example)
        val parser = TypeEncodingParser(lexer)

        val result = parser.parse()

        println(result)
    }
}
