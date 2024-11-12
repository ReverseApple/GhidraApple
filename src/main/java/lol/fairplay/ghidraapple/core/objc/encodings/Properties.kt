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
    UNKNOWN('?');  // no idea what this one represents.

    companion object {
        fun fromCode(code: Char): PropertyAttribute? {
            return PropertyAttribute.entries.find {it.code == code}
        }
    }
}

data class EncodedProperty(
    val attributes: List<PropertyAttribute>,
    val type: TypeNode?,
    val backingIvar: String? = null,
)


fun parseEncodedProperty(input: String): EncodedProperty {
    val stmts = input.split(',')
    var type: TypeNode? = null
    var ivarName: String? = null
    val attributes = mutableListOf<PropertyAttribute>()

    for (a in stmts) {
        val signal = PropertyAttribute.fromCode(a[0])!!
        when (signal) {
            PropertyAttribute.TYPE_ENCODING -> {
                a.substring(1).let {
                   val parser = TypeEncodingParser(EncodingLexer(it))
                   type = parser.parse()
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

