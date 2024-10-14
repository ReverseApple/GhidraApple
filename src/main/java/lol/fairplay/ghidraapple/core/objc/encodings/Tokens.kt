package lol.fairplay.ghidraapple.core.objc.encodings

import lol.fairplay.ghidraapple.core.objc.encodings.Token.NumberToken


sealed class Token {
    data class PrimitiveType(val type: Char) : Token()

    data class ObjectType(val type: Char = '@') : Token()
    data class PointerType(val type: Char = '^') : Token()
    data class AnonymousType(val type: Char = '?') : Token()
    data class SelectorType(val type: Char = ':') : Token()

    data class StructOpen(val type: Char = '{') : Token()
    data class StructClose(val type: Char = '}') : Token()
    data class ArrayOpen(val type: Char = '[') : Token()
    data class ArrayClose(val type: Char = ']') : Token()

    data class Identifier(val name: String) : Token()

    data class FieldSeparator(val type: Char = '=') : Token()

    data class StringLiteral(val value: String) : Token()
    data class Offset(val value: Int) : Token()
    data class Size(val value: Int) : Token()

    object EndOfFile : Token()
}

