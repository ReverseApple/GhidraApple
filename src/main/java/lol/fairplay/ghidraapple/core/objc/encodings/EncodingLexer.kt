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
                advance()
                if (structBegin) {
                    val id = collectIdentifierToken()
                    structBegin = false
                    return id
                }

                return Token.PrimitiveType(currentChar)
            }
            else -> {
                TODO()
            }
        }
    }

    private fun collectIdentifierToken(): Token.Identifier {
        val start = pos
        while (currentChar.isLetterOrDigit()) {
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

        return Token.StringLiteral(input.substring(start, pos))
    }

}
