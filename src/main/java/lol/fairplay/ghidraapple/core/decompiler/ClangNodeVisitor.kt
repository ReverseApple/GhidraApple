package lol.fairplay.ghidraapple.core.decompiler

import ghidra.app.decompiler.*

open class ClangNodeVisitor {

    var depth = 0

    fun visit(node: ClangNode) {
        when (node) {
            // these occur the most, so I'm placing them at the top.
            is ClangBreak -> visitBreak(node)
            is ClangSyntaxToken -> visitSyntaxToken(node)

            is ClangVariableDecl -> visitVariableDecl(node)
            is ClangStatement -> visitStatement(node)
            is ClangFuncProto -> visitFuncProto(node)
            is ClangReturnType -> visitReturnType(node)
            is ClangFunction -> visitFunction(node)
            is ClangCaseToken -> visitCaseToken(node)
            is ClangTypeToken -> visitTypeToken(node)
            is ClangLabelToken -> visitLabelToken(node)
            is ClangCommentToken -> visitCommentToken(node)
            is ClangFieldToken -> visitFieldToken(node)
            is ClangOpToken -> visitOpToken(node)
            is ClangVariableToken -> visitVariableToken(node)
            is ClangFuncNameToken -> visitFuncNameToken(node)
            else -> {
                if (node is ClangTokenGroup)
                    genericVisit(node)
            }
        }
    }

    fun genericVisit(node: ClangNode) {
        depth++
        val children = getChildrenList(node)
        for (c in children) {
            visit(c)
        }
        depth--
    }

    open fun visitVariableDecl(node: ClangVariableDecl) {
        genericVisit(node)
    }

    open fun visitStatement(node: ClangStatement) {
        genericVisit(node)
    }

    open fun visitFuncProto(node: ClangFuncProto) {
        genericVisit(node)
    }

    open fun visitReturnType(node: ClangReturnType) {
        genericVisit(node)
    }

    open fun visitFunction(node: ClangFunction) {
        genericVisit(node)
    }

    open fun visitCaseToken(node: ClangCaseToken) {
        genericVisit(node)
    }

    open fun visitTypeToken(node: ClangTypeToken) {
        genericVisit(node)
    }

    open fun visitLabelToken(node: ClangLabelToken) {
        genericVisit(node)
    }

    open fun visitCommentToken(node: ClangCommentToken) {
        genericVisit(node)
    }

    open fun visitFieldToken(node: ClangFieldToken) {
        genericVisit(node)
    }

    open fun visitOpToken(node: ClangOpToken) {
        genericVisit(node)
    }

    open fun visitVariableToken(node: ClangVariableToken) {
        genericVisit(node)
    }

    open fun visitFuncNameToken(node: ClangFuncNameToken) {
        genericVisit(node)
    }

    open fun visitBreak(node: ClangBreak) {
        genericVisit(node)
    }

    open fun visitSyntaxToken(node: ClangSyntaxToken) {
        genericVisit(node)
    }
}
