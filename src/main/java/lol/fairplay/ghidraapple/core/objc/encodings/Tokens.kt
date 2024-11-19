package lol.fairplay.ghidraapple.core.objc.encodings


sealed class Token {
    data class PrimitiveType(val type: Char) : Token()
    data class TypeModifier(val value: Char) : Token()

    // Special types...
    data class ObjectType(val type: Char = '@') : Token()
    data class PointerType(val type: Char = '^') : Token()
    data class SelectorType(val type: Char = ':') : Token()
    data class ClassObjectType(val type: Char = '#') : Token()
    data class BitfieldType(val type: Char = 'b') : Token()

    // Wrappers...
    data class StructOpen(val type: Char = '{') : Token()
    data class StructClose(val type: Char = '}') : Token()
    data class UnionOpen(val type: Char = '(') : Token()
    data class UnionClose(val type: Char = ')') : Token()
    data class ArrayOpen(val type: Char = '[') : Token()
    data class ArrayClose(val type: Char = ']') : Token()
    data class BlockOpen(val type: Char = '<') : Token()
    data class BlockClose(val type: Char = '>') : Token()

    data class Anonymous(val type: Char = '?') : Token()
    data class Identifier(val name: String) : Token()

    data class FieldSeparator(val type: Char = '=') : Token()

    data class StringLiteral(val value: String) : Token()
    data class NumberLiteral(val value: Int) : Token()

    object EndOfFile : Token()

}

