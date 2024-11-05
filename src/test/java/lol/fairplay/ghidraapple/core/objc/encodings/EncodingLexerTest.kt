package lol.fairplay.ghidraapple.core.objc.encodings

import kotlin.test.Test

class EncodingLexerTest {

    @Test
    fun test_Lexer() {
        val test = "v24@0:8@16"
//        val test = "{test=i{Something=\"field1\"i\"field2\"Q}}"
//        val test = "{?=\"sizeInLinks\"b1\"originalSizeInLinks\"b1\"expandSmallerObjects\"b1}"
//        val test = "{another_test=}"

//        val test = "{Person=[50c]b7b1df{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}](?=[50c][15c][30c])i}"
        val lexer = EncodingLexer(test)

        var token = lexer.getNextToken()
        while (token != Token.EndOfFile) {
            println(token)
            token = lexer.getNextToken()
        }
    }

    @Test
    fun test_SignatureLexing() {
        val example = "B40@0:8@\"NSApplication\"16@\"NSUserActivity\"24@?<v@?@\"NSArray\">32"
        val lexer = EncodingLexer(example)
        
        var token = lexer.getNextToken()
        while (token != Token.EndOfFile) {
            println(token)
            token = lexer.getNextToken()
        }
    }

}
