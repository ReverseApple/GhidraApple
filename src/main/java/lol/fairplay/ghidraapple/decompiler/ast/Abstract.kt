package lol.fairplay.ghidraapple.decompiler.ast

open class Node

open class Expression : Node()

sealed class Statement : Node() {
    data class ExpressionStatement(val expression: Expression) : Statement()
}
