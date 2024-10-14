package lol.fairplay.ghidraapple.core.objc.encodings


const val EOF_RAW = '\u0000'


class EncodingLexer(private val input: String) {

    private var pos = 0

    // --- context flags ---
    private var structBegin = false

    private val currentChar: Char
        get() = if (pos < input.length) input[pos] else EOF_RAW

    private fun advance() {
        pos++
    }

    private fun peek(n: Int): Char {
        return if (pos + n < input.length) input[pos + n] else EOF_RAW
    }

    fun getNextToken() : Token {
        while (currentChar != EOF_RAW) {
            val token = tryGetToken() ?: continue
            return token
        }
        return Token.EndOfFile
    }

    private fun tryGetToken() : Token? {
        return when (currentChar) {
            '"' -> {
                advance()
                return collectStringLiteralToken()
            }
            '{' -> {
                advance()
                structBegin = true
                return Token.StructOpen()
            }
            '}' -> {
                advance()
                return Token.StructClose()
            }
            '[' -> {
                advance()
                return Token.ArrayOpen()
            }
            ']' -> {
                advance()
                return Token.ArrayClose()
            }
            '=' -> {
                advance()
                return Token.FieldSeparator()
            }
            '?' -> {
                advance()
                if (structBegin) {
                    structBegin = false
                }

                return Token.AnonymousType()
            }
            '@' -> {
                advance()
                return Token.ObjectType()
            }
            '^' -> {
                advance()
                return Token.PointerType()
            }
            ':' -> {
                advance()
                return Token.SelectorType()
            }
            in 'a'..'z', in 'A'..'Z', '_' -> {
                if (structBegin) {
                    val id = collectIdentifierToken()
                    structBegin = false
                    return id
                }
                return Token.PrimitiveType(currentChar)
                    .also { advance() }
            }
            in '0'..'9' -> {
                return collectNumberLiteralToken()
            }
            else -> {
                throw Exception("Unexpected character: $currentChar at position $pos")
            }
        }
    }

    private fun collectNumberLiteralToken(): Token.NumberLiteral {
        val start = pos
        while (currentChar in '0'..'9') {
            advance()
        }
        val result = input.substring(start, pos).toInt()
        return Token.NumberLiteral(result)
    }

    private fun collectIdentifierToken(): Token.Identifier {
        val start = pos
        while (currentChar.isLetterOrDigit() || currentChar == '_') {
            advance()
        }
        return Token.Identifier(input.substring(start, pos))
    }

    private fun collectStringLiteralToken(): Token.StringLiteral {
        val start = pos
        while (currentChar != EOF_RAW) {
            if (currentChar == '"' && peek(-1) != '\\') {
                break
            }
            advance()
        }

        return Token.StringLiteral(input.substring(start, pos)).also { advance() }
    }

}
