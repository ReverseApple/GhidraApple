package lol.fairplay.ghidraapple.analysis.langannotation.objc

import ghidra.app.decompiler.ClangFuncNameToken
import ghidra.app.decompiler.ClangNode
import ghidra.app.decompiler.ClangOpToken
import ghidra.app.decompiler.ClangVariableToken
import ghidra.program.model.address.Address
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SymbolType
import ghidra.util.task.TaskMonitor

import lol.fairplay.ghidraapple.analysis.selectortrampoline.SelectorTrampolineAnalyzer
import lol.fairplay.ghidraapple.core.decompiler.*


class ObjCFunctionAnnotator(private val function: Function, private val monitor: TaskMonitor) {
    // The main responsibility of this mechanism is finding out where to decompile and collecting auxiliary data.

    private val decompiler = DecompiledFunctionProvider(function.program)
    private val program = function.program

    val decompileResults = decompiler.getDecompiled(function, 60)
    val stmtStack = ArrayDeque<ClangNode>()
    val state = mutableMapOf<ClangVariableToken, List<ClangNode>?>()
    val objCState = mutableMapOf<ClangVariableToken, OCMethodCall>()

    val TRAMPOLINE_TAG =
        program.functionManager.functionTagManager.getFunctionTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)

    private fun isSelector(function: Function): Boolean {
        return function.tags.contains(TRAMPOLINE_TAG)
    }

    private fun setComment(address: Address, comment: String) {
        val transaction = program.startTransaction("Set Comment")
        program.listing.setComment(address, CodeUnit.PRE_COMMENT, comment)
        program.endTransaction(transaction, true)
    }

    fun run() {
        // FIXME: this is a *really* dirty and (probably) naive implementation of this feature.
        //  This is to be rewritten either when richer semantic analysis infrastructure exists,
        //  or we can try to get a better implementation to upstream Ghidra.

        monitor.message = "Extracting function statements..."
        val rootFunction = decompileResults.cCodeMarkup
        val statements = getStatements(rootFunction)

        monitor.message = "Annotating Objective-C..."

        for (statement in statements) {
            val tokens = TokenScanner(getChildrenList(statement))

            val isAssignment = tokens.getNode<ClangOpToken>().let { it != null && it.toString() == "=" }
            val isFunctionCall = tokens.getNode<ClangFuncNameToken>() != null

            if (isFunctionCall) {
                val (functionArgs, calledFunction) = parseObjCRelatedFunctionCall(tokens) ?: continue

                when (calledFunction.name) {

                    "_objc_retainAutoreleasedReturnValue" -> {
                        // precondition: call argument is the result of an objective-c call.
                        if (isAssignment) {
                            tokens.rewind()
                            val assignment = parseAssignment(tokens) ?: throw Error("This should be impossible - 1")
                            assert(assignment.first in objCState)

                            // if and only if assignment.first is used ONCE and ONLY in another Objective-C selector,
                            //  we do not decompile the call.
                            val usedStatements = getUsage(rootFunction, assignment.first)
                                .filter {
                                    it != assignment.first
                                }.map {
                                    // map each usage to it's parent statement...
                                    it.Parent()
                                }.filter {
                                    TokenScanner(getChildrenList(it)).getNode<ClangFuncNameToken>()
                                        ?.toString() != "_objc_release"
                                }.filterNotNull().toSet()

                            if (usedStatements.size == 1) {
                                // test if it's used by another selector
                                val usage = usedStatements.toList()[0]
                                val usageTokens = TokenScanner(getChildrenList(usage))

                                usageTokens.getNode<ClangFuncNameToken>()?.let {
                                    val symbol = program.symbolTable.getSymbols(it.toString()).find {
                                        it.symbolType == SymbolType.FUNCTION && isSelector(
                                            program.functionManager.getFunctionAt(
                                                it.address
                                            )
                                        )
                                    }
                                    if (symbol == null) {
                                        // if it's not another selector, decompile the method.
                                        val decompiled = objCState[assignment.first]!!.decompile(
                                            DecompileState(
                                                rootFunction,
                                                objCState
                                            )
                                        )
                                        setComment(
                                            statement.maxAddress.add(1),
                                            "c1 ${assignment.first} = $decompiled"
                                        )
                                    }
                                }
                            } else {
                                objCState[assignment.first]?.let {
                                    val decompiled = it.decompile(DecompileState(rootFunction, objCState))
                                    setComment(
                                        statement.maxAddress.add(1),
                                        "${assignment.first} = $decompiled"
                                    )
                                }
                            }
                        }
                    }

                    "_objc_alloc" -> {
                        // precondition: call argument is an _OBJC_CLASS_$_
                        if (isAssignment) {
                            // synthesize an alloc method call object, and push it to the objc state.
                            tokens.rewind()
                            val assignment = parseAssignment(tokens) ?: throw Error("This should be impossible - 2")

                            val message = OCMessage(listOf("alloc"), null)
                            val classVar = functionArgs!![0].find {
                                it.toString().startsWith("PTR__OBJC_CLASS_\$_")
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
                                val methodCall =
                                    OCMethodCall.TryParseFromTrampolineCall(calledFunction.name, functionArgs)

                                methodCall.let { method ->
                                    // if it's an assignment, find it's relevant RARV call and then push the method call
                                    // to the objective-c state.
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
                                                && funcNameToken.toString() == "_objc_retainAutoreleasedReturnValue"
                                            ) {
                                                val retvalAssignment = parseAssignment(stmtTokens)!!

                                                objCState[retvalAssignment.first] = methodCall
                                                return@let
                                            }
                                            // test on FUN_10006dcfc
                                        }
                                    } else {
                                        // If it's not an assignment, decompile the call on the spot.
                                        setComment(
                                            statement.maxAddress.add(1),
                                            method.decompile(DecompileState(rootFunction, objCState))
                                        )
                                    }
                                }
                            }
                        }
                    }
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
