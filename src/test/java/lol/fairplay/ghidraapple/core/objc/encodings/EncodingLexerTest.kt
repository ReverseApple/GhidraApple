package lol.fairplay.ghidraapple.core.objc.encodings

import kotlin.test.Test

class EncodingLexerTest {

    @Test
    fun test_Lexer() {
//        val test = "@48@0:8@16q24@32@40"
//        val test = "{test=i{Something=\"field1\"i\"field2\"Q}}"
//        val test = "{?=\"sizeInLinks\"b1\"originalSizeInLinks\"b1\"expandSmallerObjects\"b1}"
//        val test = "{another_test=}"

        val test = "{Person=[50c]b7b1df{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}](?=[50c][15c][30c])i}"
        val lexer = EncodingLexer(test)

        var token = lexer.getNextToken()
        while (token != Token.EndOfFile) {
            println(token)
            token = lexer.getNextToken()
        }
    }

}
