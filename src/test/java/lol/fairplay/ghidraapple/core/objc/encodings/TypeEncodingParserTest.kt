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


    @Test
    fun test_ParseBulk() {
        val examples = listOf(
            "{z_stream_s=\"next_in\"*\"avail_in\"I\"total_in\"Q\"next_out\"*\"avail_out\"I\"total_out\"Q\"msg\"*\"state\"^{internal_state}\"zalloc\"^?\"zfree\"^?\"opaque\"^v\"data_type\"i\"adler\"Q\"reserved\"Q}",
            "{Person=[50c]b7b1df{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}](?=[50c][15c][30c])i}"
        )

        for (ex in examples) {
            val lexer = EncodingLexer(ex)
            val parser = TypeEncodingParser(lexer)
            val result = parser.parse()

            val jsonVisitor = JSONConversionVisitor()
            result.accept(jsonVisitor)
            println(jsonVisitor.getJSON()?.toString(2))
        }

    }

    @Test
    fun test_ParseSignature() {

        val examples = listOf(
            "B40@0:8@\"NSApplication\"16@\"NSUserActivity\"24@?<v@?@\"NSArray\">32"
                    to EncodedSignatureType.METHOD_SIGNATURE,
            "#16@0:8"
                    to EncodedSignatureType.METHOD_SIGNATURE,
        )

        for ((sig, type) in examples) {
            val lexer = EncodingLexer(sig)
            val parser = SignatureParser(lexer, type)
            val result = parser.parse()

            println(result)
        }
    }
}
