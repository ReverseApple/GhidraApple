package lol.fairplay.ghidraapple.core.objc.encodings

import kotlin.reflect.KClass

class TypeEncodingParser(val lexer: EncodingLexer) {
    var currentToken = lexer.getNextToken()

    fun parse(): TypeNode {
        return parseType()
    }

    private fun parseType(): TypeNode {
        return when (currentToken) {
            is Token.StructOpen -> parseStruct()
            is Token.ArrayOpen -> parseArray()
            is Token.PrimitiveType -> parsePrimitive()
            else -> throw IllegalArgumentException("Unexpected token: $currentToken")
        }
    }

    private fun parsePrimitive(): TypeNode.Primitive {
        val primitiveType = (currentToken as Token.PrimitiveType).type
        nextToken()
        return TypeNode.Primitive(primitiveType.toString())
    }

    private fun parseStruct(): TypeNode.Struct {
        expectToken<Token.StructOpen>()

        val structName = expectOneOf(Token.Identifier::class, Token.Anonymous::class).let {
            if (it is Token.Identifier) it.name else null
        }

        expectToken<Token.FieldSeparator>()

        val fields = mutableListOf<Pair<String?, TypeNode>>()

        while (currentToken !is Token.StructClose) {
            var name: String? = null
            if (currentToken is Token.StringLiteral) {
                name = (currentToken as Token.StringLiteral).value
                nextToken()
            }

            fields.add(name to parseType())
        }

        expectToken<Token.StructClose>()
        return TypeNode.Struct(structName, fields)
    }

    private fun parseArray(): TypeNode.Array {
        expectToken<Token.ArrayOpen>()
        val size = expectToken<Token.NumberLiteral>().value
        val elementType = parseType()
        expectToken<Token.ArrayClose>()
        return TypeNode.Array(size, elementType)
    }

    private fun expectOneOf(vararg tokenTypes: KClass<out Token>): Token {
        val token = currentToken
        nextToken()
        if (tokenTypes.any { it.isInstance(token) }) {
            return token
        } else {
            throw IllegalArgumentException("Expected one of ${tokenTypes.joinToString()}, but got $token")
        }
    }

    private inline fun <reified T : Token> expectToken(): T {
        val token = currentToken
        nextToken()
        if (token is T) {
            return token
        } else {
            throw IllegalArgumentException("Expected token ${T::class} but found ${token::class}")
        }
    }

    private fun nextToken() {
        currentToken = lexer.getNextToken()
    }
}
