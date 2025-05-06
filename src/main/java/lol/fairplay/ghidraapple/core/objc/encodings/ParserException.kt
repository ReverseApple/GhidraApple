package lol.fairplay.ghidraapple.core.objc.encodings

class ParserException(
    // The input that caused the exception. We use the lexer instead of the string so we don't accidentally mix up
    // the two string arguments
    val lexer: EncodingLexer,
    message: String? = null,
    cause: Throwable? = null,
) : Exception(message, cause) {
    override fun toString(): String = "ParserException(input='${lexer.input}', message='${message ?: ""}', cause=${cause?.message})"
}
