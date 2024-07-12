package lol.fairplay.ghidraapple.analysis.langannotation.objc

import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.ClangTokenGroup
import ghidra.app.decompiler.ClangVariableToken
import lol.fairplay.ghidraapple.core.decompiler.ArgumentList
import lol.fairplay.ghidraapple.core.decompiler.TokenScanner


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

private fun stringifyField(field: Field, rootFunction: ClangTokenGroup, objCState: MutableMap<ClangVariableToken, OCMethodCall>): String {
    return when (field) {
        is Field.Tokens -> {
            val scanner = TokenScanner(field.data)
            val variableToken = scanner.getNode<ClangVariableToken>()

            if (variableToken != null) {
                if (variableToken in objCState)
                    return objCState[variableToken]!!.decompile(rootFunction, objCState)
                else /*if (variableToken.toString().startsWith("cf_")){

                } else*/ if (scanner.getString(".") != null && field.data.size == 3) {
                    return variableToken.toString()
                }
            }

            return field.data.joinToString("")
        }
        else -> field.toString()
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

            val stringArg = stringifyField(parts[i], rootFunction, objCState)
            result.add("${names[i]}:${stringArg}")
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
                // edit: sometimes, it appears to be (recv, garbage, arg1,arg2,..., argN)
                //  and other times, it's (arg1, recv, garbage, arg2, arg3, ..., argN)
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
        val message = message.decompile(rootFunction, objCState)
        val recieverString = stringifyField(recv, rootFunction, objCState)

        return "[$recieverString $message]"
    }
}
