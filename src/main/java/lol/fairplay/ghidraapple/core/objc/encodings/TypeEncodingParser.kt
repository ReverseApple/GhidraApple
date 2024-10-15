package lol.fairplay.ghidraapple.core.objc.encodings

import kotlin.reflect.KClass

class TypeEncodingParser(val lexer: EncodingLexer) {
    var currentToken = lexer.getNextToken()

    fun parse(): TypeNode {
        return parseType()
    }

    private fun parseType(): TypeNode {
        return when (currentToken) {
            is Token.StructOpen -> parseStructOrClassObject()
            is Token.BitfieldType -> parseBitfield()
            is Token.ArrayOpen -> parseArray()
            is Token.PrimitiveType -> parsePrimitive()
            is Token.UnionOpen -> parseUnion()
            is Token.PointerType -> parsePointer()
            is Token.ObjectType -> parseObject()
            else -> throw IllegalArgumentException("Unexpected token: $currentToken")
        }
    }

    private fun parseObject(): TypeNode {
        expectToken<Token.ObjectType>()

        if (currentToken is Token.Anonymous) {
            nextToken()
            return TypeNode.Block
        } else if (currentToken is Token.StringLiteral) {
            val name = (currentToken as Token.StringLiteral).value.also { nextToken() }
            return TypeNode.Object(name)
        } else {
            return TypeNode.Object(null)
        }
    }

    private fun parsePointer(): TypeNode {
        expectToken<Token.PointerType>()

        if (currentToken is Token.Anonymous) {
            nextToken()
            return TypeNode.FunctionPointer
        }

        val pointee = parseType()
        return TypeNode.Pointer(pointee)
    }

    private fun parseBitfield(): TypeNode.Bitfield {
        expectToken<Token.BitfieldType>()
        val size = expectToken<Token.NumberLiteral>().value
        return TypeNode.Bitfield(size)
    }

    private fun parsePrimitive(): TypeNode.Primitive {
        val primitiveType = (currentToken as Token.PrimitiveType).type
        nextToken()
        return TypeNode.Primitive(primitiveType)
    }

    private fun parseStructOrClassObject(): TypeNode {
        expectToken<Token.StructOpen>()

        val identifier = expectOneOf(Token.Identifier::class, Token.Anonymous::class).let {
            if (it is Token.Identifier) it.name else null
        }

        if (currentToken is Token.StructClose) {
            nextToken()
            return TypeNode.Struct(identifier, null)
        }

        expectToken<Token.FieldSeparator>()

        var isClass = false
        if (currentToken is Token.ClassObjectType) {
            nextToken()
            isClass = true
        }

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

        return if (isClass) {
            TypeNode.ClassObject(identifier, fields)
        } else {
            TypeNode.Struct(identifier, fields)
        }
    }

    private fun parseUnion(): TypeNode.Union {
        expectToken<Token.UnionOpen>()

        val unionName = expectOneOf(Token.Identifier::class, Token.Anonymous::class).let {
            if (it is Token.Identifier) it.name else null
        }

        expectToken<Token.FieldSeparator>()

        val fields = mutableListOf<Pair<String?, TypeNode>>()
        while (currentToken !is Token.UnionClose) {
            var name: String? = null
            if (currentToken is Token.StringLiteral) {
                name = (currentToken as Token.StringLiteral).value
                nextToken()
            }

            fields.add(name to parseType())
        }

        expectToken<Token.UnionClose>()

        return TypeNode.Union(unionName, fields)
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
