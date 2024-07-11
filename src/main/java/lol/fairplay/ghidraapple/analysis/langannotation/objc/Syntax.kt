package lol.fairplay.ghidraapple.analysis.langannotation.objc

import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.ClangTokenGroup
import ghidra.app.decompiler.ClangVariableToken
import lol.fairplay.ghidraapple.core.decompiler.ArgumentList


sealed class Field {

    companion object {
        private inline fun <reified T> isType(value: Any): Boolean = value is T

        fun ConvertFrom(value: Any?): Field {
            return when (value) {
                is OCMethodCall -> MethodCall(value)
                null -> Unknown
                else -> {
                    if (isType<List<ClangNode>>(value)) {
                        return Tokens(value as List<ClangNode>)
                    }
                    throw Exception("Failed to convert $value to Field")
                }
            }
        }
    }

    data class Tokens(val data: List<ClangNode>) : Field()
    data class MethodCall(val data: OCMethodCall) : Field()

    data object Unknown : Field() {
        override fun toString(): String {
            return "<UNKNOWN>"
        }
    }

}

private fun fieldToString(field: Field, rootFunction: ClangTokenGroup, objCState: MutableMap<ClangVariableToken, OCMethodCall>): String {
    return when (field) {
        is Field.Tokens -> field.data.joinToString()
        is Field.MethodCall -> field.data.decompile(rootFunction, objCState)
        is Field.Unknown -> Field.Unknown.toString()
    }
}


data class OCMessage(val names: List<String>, val parts: List<Field>?) {

    init {
        assert((!parts.isNullOrEmpty() && names.size == parts.size) || names.size == 1)
    }

    fun decompile(rootFunction: ClangTokenGroup, objCState: MutableMap<ClangVariableToken, OCMethodCall>): String {

        if (parts.isNullOrEmpty()) {
            return names[0]
        }

        val result = mutableListOf<String>()
        for (i in names.indices) {
            // todo: if a variable is an objective-c method call, and there is only one reference to that call (we are that reference),
            //  inline the call.
            result.add("${names[i]}:${parts[i]}")
        }


        return result.joinToString(" ")
    }
}

data class OCMethodCall(
    val recv: Field,
    val message: OCMessage
) {

    companion object {
        fun TryParseFromTrampolineCall(functionName: String, args: ArgumentList?, isArm: Boolean = true): OCMethodCall? {
            val funcArgs = args?.toMutableList()

            val receivingObject = Field.ConvertFrom(funcArgs?.removeAt(0))

            if (isArm && !funcArgs.isNullOrEmpty()) {
                // second argument does not appear to be meaningful on arm from what I've seen.
                funcArgs.removeAt(0)
            }

            // Parse message...
            val selectorStrings = functionName.split(":").filter { it.trim().isNotEmpty() }
            val fields: List<Field>? = funcArgs?.map { Field.Tokens(it) }
            val message = OCMessage(selectorStrings, fields)

            return OCMethodCall(receivingObject, message)
        }
    }

    fun decompile(rootFunction: ClangTokenGroup, objCState: MutableMap<ClangVariableToken, OCMethodCall>): String {
        val receiver = fieldToString(recv, rootFunction, objCState)
        val message = message.decompile(rootFunction, objCState)

        return "[$receiver $message]"
    }
}
