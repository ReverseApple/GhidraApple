package lol.fairplay.ghidraapple.core.decompiler

import ghidra.app.decompiler.ClangNode


fun getChildrenList(node: ClangNode): List<ClangNode> {
    val result = mutableListOf<ClangNode>()
    for (i in 0..<node.numChildren())
        result.add(node.Child(i))
    return result
}


class Scanner(private val nodes: List<ClangNode>) {
    private var index = 0

    fun hasMore() = index < nodes.size

    fun pop(): ClangNode {
        val node = nodes[index]
        index++
        return node
    }

    inline fun <reified T: ClangNode> nextType(): T? {
        while (hasMore()) {
            val node = pop()
            if (node is T) return node
        }
        return null
    }

}
