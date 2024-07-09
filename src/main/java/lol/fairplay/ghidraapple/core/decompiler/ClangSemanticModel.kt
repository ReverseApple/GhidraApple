package lol.fairplay.ghidraapple.core.decompiler

import ghidra.app.decompiler.ClangNode
import java.util.*

class ClangSemanticModel {

    private var nodeStack = ArrayDeque<ClangNode>()

    fun pushNode(node: ClangNode) = nodeStack.push(node)
    fun popNode() = nodeStack.pop()

}
