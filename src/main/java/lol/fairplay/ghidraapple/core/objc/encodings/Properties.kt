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
    NULLABLE('?'),
    ;

    companion object {
        fun fromCode(code: Char): PropertyAttribute? {
            return PropertyAttribute.entries.find { it.code == code }
        }
    }

    fun annotationString(): String? {
        return when (this) {
            READ_ONLY -> "readonly"
            BY_COPY -> "copy"
            BY_REFERENCE -> "retain"
            DYNAMIC -> "dynamic"
            CUSTOM_GETTER -> "getter="
            CUSTOM_SETTER -> "setter="
            BACKING_IVAR -> "ivar="
            WEAK -> "weak"
            STRONG -> "strong"
            NON_ATOMIC -> "nonatomic"
            NULLABLE -> "nullable"
            else -> null
        }
    }
}

data class EncodedProperty(
    val attributes: List<PropertyAttribute>,
    val type: Pair<TypeNode, List<SignatureTypeModifier>?>?,
    val customGetter: String? = null,
    val customSetter: String? = null,
    val backingIvar: String? = null,
)

fun parseEncodedProperty(input: String): EncodedProperty {
    println("Property: $input")
    val stmts = input.split(',')
    var type: Pair<TypeNode, List<SignatureTypeModifier>?>? = null
    var ivarName: String? = null
    val attributes = mutableListOf<PropertyAttribute>()
    var customSetter: String? = null
    var customGetter: String? = null

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
            PropertyAttribute.CUSTOM_GETTER, PropertyAttribute.CUSTOM_SETTER -> {
                a.substring(1).let {
                    if (signal == PropertyAttribute.CUSTOM_SETTER) {
                        attributes.add(PropertyAttribute.CUSTOM_SETTER)
                        customSetter = it
                    } else {
                        attributes.add(PropertyAttribute.CUSTOM_GETTER)
                        customGetter = it
                    }
                }
            }
            else -> attributes.add(signal)
        }
    }

    return EncodedProperty(attributes, type, customGetter, customSetter, ivarName)
}
