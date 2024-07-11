package lol.fairplay.ghidraapple.analysis.langannotation.objc

import ghidra.app.decompiler.ClangFuncNameToken
import ghidra.app.decompiler.ClangNode
import lol.fairplay.ghidraapple.core.decompiler.ArgumentList
import lol.fairplay.ghidraapple.core.decompiler.TokenScanner
import lol.fairplay.ghidraapple.core.decompiler.parseFunctionArgs


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

data class OCMessage(val names: List<String>, val parts: List<Field>?)

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
            val selectorStrings = functionName.split(":")
            val fields: List<Field>? = funcArgs?.map { Field.Tokens(it) }
            val message = OCMessage(selectorStrings, fields)

            return OCMethodCall(receivingObject, message)
        }
    }

    fun decompile(): String {
        TODO()
    }
}
