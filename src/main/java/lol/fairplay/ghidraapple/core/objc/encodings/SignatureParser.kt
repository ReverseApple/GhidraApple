package lol.fairplay.ghidraapple.core.objc.encodings


class SignatureParser(lexer: EncodingLexer, val sigType: EncodedSignatureType) : EncodingParser(lexer) {

    fun parse(): EncodedSignature {

        val returnType = parseType()
        val stackSize = expectToken<Token.NumberLiteral>().value
        val parameters = mutableListOf<Pair<TypeNode, Int>>()

        expectToken<Token.ObjectType>()
        when (sigType) {
            EncodedSignatureType.METHOD_SIGNATURE -> {
                expectToken<Token.NumberLiteral>()
                expectToken<Token.SelectorType>()
                expectToken<Token.NumberLiteral>()
            }
            EncodedSignatureType.BLOCK_SIGNATURE -> {
                expectToken<Token.Anonymous>()
            }
        }

        while (lexer.latestToken != Token.EndOfFile) {
            val type = parseType()
            val offset = expectToken<Token.NumberLiteral>().value
            parameters += type to offset
        }

        return EncodedSignature(sigType, returnType, stackSize, parameters.toList())
    }

    private fun parseType(): TypeNode {
        val parser = TypeEncodingParser(lexer)
        return parser.parse()
    }

}
