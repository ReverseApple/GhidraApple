package lol.fairplay.ghidraapple.core.decompiler

import ghidra.app.decompiler.*
import ghidra.program.model.pcode.Varnode



fun getChildrenList(node: ClangNode): List<ClangNode> {
    val result = mutableListOf<ClangNode>()
    for (i in 0..<node.numChildren())
        result.add(node.Child(i))
    return result
}


class TokenScanner(var nodes: List<ClangNode>, val whitespace: Boolean = false) {
    private var index = 0

    init {
        nodes = nodes.filter{ !whitespace && it.toString().trim().isNotEmpty() }
    }

    fun hasMore() = index < nodes.size

    fun pop(): ClangNode {
        val node = nodes[index]
        index++
        return node
    }

    fun rewind() {
        index = 0
    }

    fun remaining(): List<ClangNode> {
        val result = nodes.subList(index, nodes.size)
        index = nodes.size
        return result
    }

    inline fun <reified T: ClangNode> nextType(): T? {
        while (hasMore()) {
            val node = pop()
            if (node is T) return node
        }
        return null
    }

    fun getString(str: String): ClangNode? {
        for (t in nodes) {
            if (t.toString() == str)
                return t
        }
        return null
    }

    inline fun <reified T: ClangNode> getNode(): T? {
        for (token in nodes) {
            if (token is T)
                return token
        }
        return null
    }

}

fun getUsage(root: ClangNode, variable: ClangVariableToken): List<ClangVariableToken>  {
    val usage = mutableListOf<ClangVariableToken>()

    val visitor = object : ClangNodeVisitor() {
        override fun visitVariableToken(node: ClangVariableToken) {
            if (node.varnode == variable.varnode) {
                usage.add(node)
            }
        }
    }
    visitor.visit(root)

    return usage.toList()
}

fun getStatements(node: ClangNode): List<ClangStatement> {
    val statements = mutableListOf<ClangStatement>()

    val visitor = object : ClangNodeVisitor() {
        override fun visitStatement(node: ClangStatement) {
            statements.add(node)
        }
    }
    visitor.visit(node)

    return statements.toList()
}

typealias ArgumentList = List<List<ClangNode>>
typealias Assignment = Pair<ClangVariableToken, List<ClangNode>>

fun parseFunctionArgs(tokenScanner: TokenScanner): ArgumentList? {
    var parenthesis = 0

    while(tokenScanner.nextType<ClangSyntaxToken>().toString() != "(")

    if (!tokenScanner.hasMore())
        return null

    parenthesis++

    val result = mutableListOf<List<ClangNode>>()
    val currentArg = mutableListOf<ClangNode>()

    while (parenthesis > 0) {
        val node = tokenScanner.pop()
        if(node is ClangSyntaxToken || node is ClangOpToken) {
            when (node.toString()) {
                "(" -> parenthesis++
                ")" -> parenthesis--
                "," -> {
                    if (parenthesis == 1) {
                        result.add(currentArg.toList())
                        currentArg.clear()
                        continue
                    }
                }
            }
        }
        if (parenthesis > 0) {
            currentArg.add(node)
        }
    }

    if (currentArg.isNotEmpty()) {
        result.add(currentArg.toList())
    }

    return result.toList()
}


fun parseAssignment(tokenScanner: TokenScanner): Assignment? {
    val target = tokenScanner.nextType<ClangVariableToken>() ?: return null

    while(tokenScanner.nextType<ClangOpToken>().toString() != "=");

    if (!tokenScanner.hasMore()) return null

    val value = tokenScanner.remaining()

    return Assignment(target, value)
}
