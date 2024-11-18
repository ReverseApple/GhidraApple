package lol.fairplay.ghidraapple.core.objc.encodings


enum class PropertyAttribute(val code: Char) {
    READ_ONLY('R'),
    BY_COPY('C'),
    BY_REFERENCE('&'),
    DYNAMIC('D'),
    CUSTOM_GETTER('G'),
    CUSTOM_SETTER('S'),
    BACKING_IVAR('V'),
    TYPE_ENCODING('T'),
    WEAK('W'),
    STRONG('P'),
    NON_ATOMIC('N'),
    OPTIONAL('?');

    companion object {
        fun fromCode(code: Char): PropertyAttribute? {
            return PropertyAttribute.entries.find {it.code == code}
        }
    }
}

data class EncodedProperty(
    val attributes: List<PropertyAttribute>,
    val type: Pair<TypeNode, List<SignatureTypeModifier>?>?,
    val backingIvar: String? = null,
)


fun parseEncodedProperty(input: String): EncodedProperty {
    println("Property: $input")
    val stmts = input.split(',')
    var type: Pair<TypeNode, List<SignatureTypeModifier>?>? = null
    var ivarName: String? = null
    val attributes = mutableListOf<PropertyAttribute>()

    for (a in stmts) {
        val signal = PropertyAttribute.fromCode(a[0])!!
        when (signal) {
            PropertyAttribute.TYPE_ENCODING -> {
                a.substring(1).let {
                    val lexer = EncodingLexer(it)
                    val modifiers = mutableListOf<SignatureTypeModifier>()
                    lexer.getNextToken()
                    while (lexer.latestToken is Token.TypeModifier) {
                        val code = (lexer.latestToken as Token.TypeModifier).value
                        modifiers.add(SignatureTypeModifier.fromCode(code)!!)
                        lexer.getNextToken()
                    }

                    val parser = TypeEncodingParser(lexer)
                    type = parser.parse() to if (modifiers.isNotEmpty()) modifiers else null
                }
            }
            PropertyAttribute.BACKING_IVAR -> {
                ivarName = a.substring(1)
            }
            else -> attributes.add(signal)
        }
    }

    return EncodedProperty(attributes, type, ivarName)
}

