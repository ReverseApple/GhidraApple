package lol.fairplay.ghidraapple.actions.te

import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType

fun retypeFunction(
    function: Function,
    functionDefinition: FunctionDefinition,
    program: Program,
    useTransaction: Boolean = true,
) {
    with(functionDefinition) {
        val block: () -> Unit = {
            function.updateFunction(
                callingConventionName,
                ReturnParameterImpl(returnType, program),
                arguments.map { ParameterImpl(it.name, it.dataType, program) },
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                false,
                SourceType.DEFAULT,
            )
        }
        if (useTransaction) {
            program.withTransaction<Exception>("Retype function ${function.name}") {
                block()
            }
        } else {
            block()
        }
    }
}
