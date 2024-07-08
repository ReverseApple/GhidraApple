package lol.fairplay.ghidraapple.core.decompiler

import ghidra.app.decompiler.*

class ClangNodeVisitor {

    fun visit(node: ClangNode) {
        when (node) {
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
            is ClangBreak -> visitBreak(node)
            is ClangSyntaxToken -> visitSyntaxToken(node)
        }
    }

    private fun genericVisit(node: ClangNode) {
        for (i in 0..<node.numChildren()) {
            visit(node.Child(i))
        }
    }

    fun visitVariableDecl(node: ClangVariableDecl) {
        genericVisit(node)
    }

    fun visitStatement(node: ClangStatement) {
        genericVisit(node)
    }

    fun visitFuncProto(node: ClangFuncProto) {
        genericVisit(node)
    }

    fun visitReturnType(node: ClangReturnType) {
        genericVisit(node)
    }

    fun visitFunction(node: ClangFunction) {
        genericVisit(node)
    }

    fun visitCaseToken(node: ClangCaseToken) {
        genericVisit(node)
    }

    fun visitTypeToken(node: ClangTypeToken) {
        genericVisit(node)
    }

    fun visitLabelToken(node: ClangLabelToken) {
        genericVisit(node)
    }

    fun visitCommentToken(node: ClangCommentToken) {
        genericVisit(node)
    }

    fun visitFieldToken(node: ClangFieldToken) {
        genericVisit(node)
    }

    fun visitOpToken(node: ClangOpToken) {
        genericVisit(node)
    }

    fun visitVariableToken(node: ClangVariableToken) {
        genericVisit(node)
    }

    fun visitFuncNameToken(node: ClangFuncNameToken) {
        genericVisit(node)
    }

    fun visitBreak(node: ClangBreak) {
        genericVisit(node)
    }

    fun visitSyntaxToken(node: ClangSyntaxToken) {
        genericVisit(node)
    }
}
