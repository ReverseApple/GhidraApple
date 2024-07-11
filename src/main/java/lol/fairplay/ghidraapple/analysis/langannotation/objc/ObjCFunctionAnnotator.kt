package lol.fairplay.ghidraapple.analysis.langannotation.objc

import ghidra.app.decompiler.ClangFuncNameToken
import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.ClangOpToken
import ghidra.app.decompiler.ClangVariableToken
import ghidra.program.model.address.Address
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.Function
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.selectortrampoline.SelectorTrampolineAnalyzer
import lol.fairplay.ghidraapple.core.decompiler.*


class ObjCFunctionAnnotator(private val function: Function, private val monitor: TaskMonitor) {

    private val decompiler = DecompiledFunctionProvider(function.program)
    private val program = function.program

    val TRAMPOLINE_TAG =
        program.functionManager.functionTagManager.getFunctionTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)

    private fun isSelector(function: Function): Boolean {
        return function.tags.contains(TRAMPOLINE_TAG)
    }

    private fun setComment(address: Address, comment: String) {
        val transaction = program.startTransaction("Set Comment")
        program.listing.setComment(address, CodeUnit.PRE_COMMENT, comment)
        program.endTransaction(transaction, true);
    }

    fun run() {
        // TODO: this is a *really* dirty and (probably) naive implementation of this feature.
        //  This is to be rewritten either when richer semantic analysis infrastructure exists,
        //  or we can try to get a better implementation to upstream Ghidra.

        monitor.message = "Extracting function statements..."
        val decompileResults = decompiler.getDecompiled(function, 60)
        val rootFunction = decompileResults.cCodeMarkup

        monitor.message = "Annotating Objective-C..."
        val statements = getStatements(rootFunction)
        val stmtStack = ArrayDeque<ClangNode>()

        val state = mutableMapOf<ClangVariableToken, List<ClangNode>?>()
        val objCState = mutableMapOf<ClangVariableToken, OCMethodCall>()

        for (statement in statements) {
            val tokens = TokenScanner(getChildrenList(statement))

            val isAssignment = tokens.getNode<ClangOpToken>().let { it != null && it.toString() == "=" }
            val isFunctionCall = tokens.getNode<ClangFuncNameToken>() != null

            if (isFunctionCall) {
                val functionNode = tokens.getNode<ClangFuncNameToken>()!!
                val functionArgs = parseFunctionArgs(tokens)

                val calledFunction = program.symbolTable.getSymbols(functionNode.toString()).map {
                    program.functionManager.getFunctionAt(it.address)
                }.find { it != null && (it.tags.contains(TRAMPOLINE_TAG) || it.name.startsWith("_objc_")) }!!


                when (calledFunction.name) {
                    "_objc_retainAutoreleasedReturnValue" -> {
                        // precondition: call argument is the result of an objective-c call.
                        if (isAssignment) {
                            tokens.rewind()
                            val assignment = parseAssignment(tokens) ?: throw Error("This should be impossible - 1")
                            assert(assignment.first in objCState)
                        }
                    }

                    "_objc_alloc" -> {
                        // precondition: call argument is an _OBJC_CLASS_$_
                        if (isAssignment) {
                            tokens.rewind()
                            val assignment = parseAssignment(tokens) ?: throw Error("This should be impossible - 2")

                            val message = OCMessage(listOf("alloc"), null)
                            val classVar = functionArgs!![0].find {
                                it.toString().startsWith("_OBJC_CLASS_\$_")
                            }

                            val methodCall = OCMethodCall(Field.Tokens(listOf(classVar!!)), message)
                            objCState[assignment.first] = methodCall
                        }
                    }

//                    "_objc_release" -> {
//                        // precondition: call argument is the result of an objective-c call.
//
//                    }

                    else -> {
                        if (isSelector(calledFunction)) {
                            if (!functionArgs.isNullOrEmpty()) {
                                var methodCall =
                                    OCMethodCall.TryParseFromTrampolineCall(calledFunction.name, functionArgs)

                                methodCall?.let {

                                    if (isAssignment) {
                                        tokens.rewind()
                                        val assignment =
                                            parseAssignment(tokens) ?: throw Error("This should be impossible - 3")

                                        //todo: Find the related _objc_retainAutoreleasedReturnValue statement...

                                        objCState[assignment.first] = it
                                    } else {
                                        setComment(statement.maxAddress.add(1), it.decompile(rootFunction, objCState))
                                    }

                                }
                            }
                        }
                    }
                }

                // If it's also an assignment... do something?
                if (isAssignment) {
                    val assignmentTarget = tokens.getNode<ClangVariableToken>()!!

                    val usage = getUsage(rootFunction, assignmentTarget).toMutableList()
                    usage.remove(assignmentTarget)

                }

            } else if (isAssignment) {
                // update variable state mapping
                val assignment = parseAssignment(tokens)!!
                state[assignment.first] = assignment.second
            }

            stmtStack.add(statement)
        }
    }
}
