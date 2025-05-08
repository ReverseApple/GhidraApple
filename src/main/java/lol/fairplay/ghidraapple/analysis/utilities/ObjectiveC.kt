package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Undefined8DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import lol.fairplay.ghidraapple.analysis.passes.selectortrampoline.ARCFixupInstallerAnalyzer.Companion.OBJC_WO_SEL_CC
import lol.fairplay.ghidraapple.db.Selector

fun updateFunctionSignatureFromSelector(
    func: Function,
    sel: Selector,
    recvType: Pointer? = null,
    sourceType: SourceType = SourceType.USER_DEFINED,
) {
    val program = func.program
    val idDataType = program.dataTypeManager.getDataType("/_objc2_/ID")
    val returnVariable = ReturnParameterImpl(idDataType, program)

    val parameters = mutableListOf<ParameterImpl>()
    parameters.add(ParameterImpl("recv", recvType ?: idDataType, program))
    parameterNamesForMethod(sel).forEach {
        // We use undefined8 instead of ID because of https://github.com/NationalSecurityAgency/ghidra/issues/8118
        parameters.add(ParameterImpl(it, Undefined8DataType(), program))
    }

    func.updateFunction(
        OBJC_WO_SEL_CC,
        returnVariable,
        parameters,
        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        false,
        sourceType,
    )
}

fun splitCamelCase(input: String): List<String> = input.split(Regex("(?<=[a-zA-Z])(?=[A-Z])"))

fun parameterNamesForMethod(methodName: String): List<String> {
    // todo: make this optional.
    // create parameter names, acknowledging common objective-c naming conventions.

    val keywords = listOf("with", "for", "from", "to", "in", "at")
    if (!methodName.contains(":")) {
        return listOf()
    }

    val baseNames =
        methodName
            .split(":")
            .filter { it.isNotEmpty() }
            .map { part ->
                val ccSplit = splitCamelCase(part)

                val matchIndex =
                    ccSplit.indexOfFirst {
                        it.lowercase() in keywords
                    }
                val match = ccSplit.getOrNull(matchIndex) ?: return@map part

                when (match.lowercase()) {
                    "for" -> {
                        if (part.startsWith(match)) {
                            part.substringAfter(match).replaceFirstChar { it.lowercase() }
                        } else {
                            part.substringAfter(match).replaceFirstChar { it.lowercase() }
                        }
                    }
                    in keywords -> part.substringAfter(match).replaceFirstChar { it.lowercase() }
                    else -> part
                }
            }

    val uniqueNames =
        mutableMapOf<String, Int>(
            "self" to 1,
            "selector" to 1,
        )

    val result =
        baseNames.map { name ->
            val count = uniqueNames.getOrDefault(name, 0)
            uniqueNames[name] = count + 1
            if (count > 0) "${name}_$count" else name
        }

    return result
}
