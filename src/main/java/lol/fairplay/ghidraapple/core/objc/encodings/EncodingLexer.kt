package lol.fairplay.ghidraapple.core.objc.encodings

const val EOF_RAW = '\u0000'

class EncodingLexer(private val input: String) {
    private var pos = 0
    var latestToken: Token? = null

    // --- context flags ---
    private var structOrUnionBegin = false

    private val currentChar: Char
        get() = if (pos < input.length) input[pos] else EOF_RAW

    private fun advance() {
        pos++
    }

    private fun peek(n: Int): Char {
        return if (pos + n < input.length) input[pos + n] else EOF_RAW
    }

    fun getNextToken(): Token {
        while (currentChar != EOF_RAW) {
            val token = tryGetToken() ?: continue
            latestToken = token
            return token
        }
        latestToken = Token.EndOfFile
        return Token.EndOfFile
    }

    private fun tryGetToken(): Token? {
        return when (currentChar) {
            '"' -> {
                advance()
                return collectStringLiteralToken()
            }
            '{' -> {
                advance()
                structOrUnionBegin = true
                return Token.StructOpen()
            }
            '}' -> {
                advance()
                return Token.StructClose()
            }
            '(' -> {
                advance()
                structOrUnionBegin = true
                return Token.UnionOpen()
            }
            ')' -> {
                advance()
                return Token.UnionClose()
            }
            '[' -> {
                advance()
                return Token.ArrayOpen()
            }
            ']' -> {
                advance()
                return Token.ArrayClose()
            }
            '<' -> {
                advance()
                return Token.BlockOpen()
            }
            '>' -> {
                advance()
                return Token.BlockClose()
            }
            '=' -> {
                advance()
                return Token.FieldSeparator()
            }
            '?' -> {
                advance()
                structOrUnionBegin = false

                return Token.Anonymous()
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
            '#' -> {
                advance()
                return Token.ClassObjectType()
            }
            in 'a'..'z', in 'A'..'Z', '_', '*' -> {
                if (currentChar == 'b' && peek(1).isDigit()) {
                    advance()
                    return Token.BitfieldType()
                }

                if (structOrUnionBegin) {
                    val id = collectIdentifierToken()
                    structOrUnionBegin = false
                    return id
                }

                if (currentChar in setOf('r', 'n', 'N', 'o', 'O', 'R', 'V', 'A', 'j')) {
                    return Token.TypeModifier(currentChar)
                        .also { advance() }
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
        while (currentChar !in setOf('=', '}', ')')) {
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
            .also { advance() }
    }
}
