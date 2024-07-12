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
    // The main responsibility of this mechanism is finding out where to decompile and collecting auxiliary data.

    private val decompiler = DecompiledFunctionProvider(function.program)
    private val program = function.program

    val TRAMPOLINE_TAG =
        program.functionManager.functionTagManager.getFunctionTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)

    private fun isSelector(function: Function): Boolean {
        return function.tags.contains(TRAMPOLINE_TAG)
    }

    private fun setComment(address: Address, comment: String) {
        program.listing.setComment(address, CodeUnit.PRE_COMMENT, comment)
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
                val (functionArgs, calledFunction) = parseObjCRelatedFunctionCall(tokens) ?: return

                when (calledFunction.name) {

                    "_objc_retainAutoreleasedReturnValue" -> {
                        // precondition: call argument is the result of an objective-c call.
                        if (isAssignment) {
                            tokens.rewind()
                            val assignment = parseAssignment(tokens) ?: throw Error("This should be impossible - 1")
                            assert(assignment.first in objCState)

                            // todo: decompile related objc method here if `assignment.first` is not
                            //  used in another objc context.

        //                            // if and only if assignment.first is used once in another Objective-C context,
        //                            //  we do not decompile the call.
        //                            val usages = getUsage(rootFunction, assignment.first).toMutableList()
        //                            usages.remove(assignment.first)
        //
        //                            if (usages.size == 1) {
        //                                val usage =
        //                            }
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

                    "_objc_release" -> {
                        // precondition: call argument is the result of an objective-c call.

                    }

                    else -> {
                        if (isSelector(calledFunction)) {
                            if (!functionArgs.isNullOrEmpty()) {
                                var methodCall =
                                    OCMethodCall.TryParseFromTrampolineCall(calledFunction.name, functionArgs)

                                methodCall?.let { method ->

                                    if (isAssignment) {
                                        tokens.rewind()
                                        val trampolineAssignment =
                                            parseAssignment(tokens) ?: throw Error("This should be impossible - 3")

                                        // Find the related _objc_retainAutoreleasedReturnValue statement...
                                        getUsage(rootFunction, trampolineAssignment.first).forEach {

                                            val stmtTokens = TokenScanner(getChildrenList(it.Parent()))

                                            // Ensure there's a function call in this usage.
                                            val funcNameToken = stmtTokens.getNode<ClangFuncNameToken>()

                                            if (funcNameToken != null
                                                && funcNameToken.toString() == "_objc_retainAutoreleasedReturnValue") {
                                                val retvalAssignment = parseAssignment(stmtTokens)!!

                                                objCState[retvalAssignment.first] = methodCall
                                                return@let
                                            }

                                            // test on FUN_10006dcfc

                                        }

                                    } else {
                                        setComment(
                                            statement.maxAddress.add(1),
                                            method.decompile(rootFunction, objCState)
                                        )
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

    private fun parseObjCRelatedFunctionCall(tokens: TokenScanner): Pair<ArgumentList?, Function>? {
        val functionNode = tokens.getNode<ClangFuncNameToken>()!!
        val functionArgs = parseFunctionArgs(tokens)

        val calledFunction = program.symbolTable.getSymbols(functionNode.toString()).map {
            program.functionManager.getFunctionAt(it.address)
        }.find { it != null && (it.tags.contains(TRAMPOLINE_TAG) || it.name.startsWith("_objc_")) } ?: return null
        return Pair(functionArgs, calledFunction)
    }
}
