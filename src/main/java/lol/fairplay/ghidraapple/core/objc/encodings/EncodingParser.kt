package lol.fairplay.ghidraapple.core.objc.encodings

import kotlin.reflect.KClass

abstract class EncodingParser(val lexer: EncodingLexer) {

    var currentToken = lexer.getNextToken()

    protected fun expectOneOf(vararg tokenTypes: KClass<out Token>): Token {
        val token = currentToken
        nextToken()
        if (tokenTypes.any { it.isInstance(token) }) {
            return token
        } else {
            throw IllegalArgumentException("Expected one of ${tokenTypes.joinToString()}, but got $token")
        }
    }

    protected inline fun <reified T : Token> expectToken(): T {
        val token = currentToken
        nextToken()
        if (token is T) {
            return token
        } else {
            throw IllegalArgumentException("Expected token ${T::class} but found ${token::class}")
        }
    }

    protected fun nextToken() {
        currentToken = lexer.getNextToken()
    }

}
