package lol.fairplay.ghidraapple.core.objc.encodings


class SignatureParser(lexer: EncodingLexer, val sigType: EncodedSignatureType) : EncodingParser(lexer) {

    fun parse(): EncodedSignature {
        val startingEntry = parseEntry()

        val returnType = startingEntry.first
        val rtModifiers = startingEntry.third
        val stackSize = startingEntry.second

        val parameters = mutableListOf<Triple<TypeNode, Int, List<SignatureTypeModifier>?>>()

        expectToken<Token.ObjectType>()
        when (sigType) {
            EncodedSignatureType.METHOD_SIGNATURE -> {
                expectToken<Token.NumberLiteral>()
                expectToken<Token.SelectorType>()
                expectToken<Token.NumberLiteral>()
            }
            EncodedSignatureType.BLOCK_SIGNATURE -> {
                expectToken<Token.Anonymous>()
                expectToken<Token.NumberLiteral>()
            }
        }

        while (currentToken != Token.EndOfFile) {
            val entry = parseEntry()
            parameters += entry
        }

        return EncodedSignature(sigType, returnType to rtModifiers, stackSize, parameters.toList())
    }

    private fun parseEntry(): Triple<TypeNode, Int, List<SignatureTypeModifier>?> {
        val modifiers = mutableListOf<SignatureTypeModifier>()
        while (currentToken is Token.TypeModifier) {
            val modifier = expectToken<Token.TypeModifier>()
            modifiers.add(SignatureTypeModifier.fromCode(modifier.value)!!) // if the result of fromCode is null, we have bigger problems.
        }
        val type = parseType()
        val number = expectToken<Token.NumberLiteral>().value
        return Triple(type, number, modifiers.let { if (it.isEmpty()) null else it.toList() })
    }

    private fun parseType(): TypeNode {
        val parser = TypeEncodingParser(lexer)
        return parser.parse()
    }

}

fun parseSignature(input: String, type: EncodedSignatureType): EncodedSignature {
//    println("Signature: $input")
    val lexer = EncodingLexer(input)
    val parser = SignatureParser(lexer, type)
    return parser.parse()
}
