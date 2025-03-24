package lol.fairplay.ghidraapple.core.objc.encodings

class TypeEncodingParser(lexer: EncodingLexer) : EncodingParser(lexer) {
    fun parse(): TypeNode {
        return parseType()
    }

    fun parseSequence(until: Token): List<TypeNode> {
        val result = mutableListOf<TypeNode>()
        while (currentToken::class != until::class) {
            result.add(parseType())
        }
        return result.toList()
    }

    private fun parseType(): TypeNode {
        return when (currentToken) {
            is Token.StructOpen -> parseStructOrClassObject()
            is Token.TypeModifier -> parseModifiedType()
            is Token.BitfieldType -> parseBitfield()
            is Token.ArrayOpen -> parseArray()
            is Token.PrimitiveType -> parsePrimitive()
            is Token.UnionOpen -> parseUnion()
            is Token.PointerType -> parsePointer()
            is Token.ObjectType -> parseObject()
            is Token.SelectorType -> parseSelectorType()
            is Token.ClassObjectType -> parseClassObject()
            else -> throw IllegalArgumentException("Unexpected token: $currentToken")
        }
    }

    private fun parseModifiedType(): TypeNode.ModifiedType {
        val modifier = expectToken<Token.TypeModifier>()
        val type = parseType()

        return TypeNode.ModifiedType(
            type,
            modifier.value,
        )
    }

    private fun parseSelectorType(): TypeNode {
        expectToken<Token.SelectorType>()
        return TypeNode.Selector
    }

    private fun parseClassObject(): TypeNode {
        expectToken<Token.ClassObjectType>()
        return TypeNode.ClassObject(null, null)
    }

    private fun parseBlock(): TypeNode.Block {
        /**
         * In the context of method encodings, blocks are typically represented using angle brackets.
         * ``@?<...>``
         *
         * In the context of type encodings, blocks are represented using only the ``@?`` signal.
         */

        if (currentToken !is Token.BlockOpen) {
            return TypeNode.Block(null, null)
        }

        expectToken<Token.BlockOpen>()
        val types = parseSequence(Token.BlockClose())
        expectToken<Token.BlockClose>()

        return TypeNode.Block(
            types[0],
            types.slice(1 until types.size)
                .let { if (it.isEmpty()) null else it }
                ?.map { it to null },
        )
    }

    private fun parseObject(): TypeNode {
        expectToken<Token.ObjectType>()

        if (currentToken is Token.Anonymous) {
            nextToken()
            return parseBlock()
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

        val identifier =
            expectOneOf(Token.Identifier::class, Token.Anonymous::class).let {
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

        val unionName =
            expectOneOf(Token.Identifier::class, Token.Anonymous::class).let {
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
}
