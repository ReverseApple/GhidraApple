package lol.fairplay.ghidraapple.analysis.langannotation

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.decompiler.*
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.Plugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import lol.fairplay.ghidraapple.GhidraApplePluginPackage
import lol.fairplay.ghidraapple.core.decompiler.ClangNodeVisitor
import lol.fairplay.ghidraapple.core.decompiler.DecompiledFunctionProvider


class TreePrinter : ClangNodeVisitor() {

    fun getIndent(): String {
        return " ".repeat(depth * 4)
    }

    override fun visitVariableDecl(node: ClangVariableDecl) {
        println("${getIndent()}VariableDecl node: $node")
        super.visitVariableDecl(node)
    }

    override fun visitStatement(node: ClangStatement) {
        println("${getIndent()}Statement node: $node")
        super.visitStatement(node)
    }

    override fun visitFuncProto(node: ClangFuncProto) {
        println("${getIndent()}FuncProto node: $node")
        super.visitFuncProto(node)
    }

    override fun visitReturnType(node: ClangReturnType) {
        println("${getIndent()}ReturnType node: $node")
        super.visitReturnType(node)
    }

    override fun visitFunction(node: ClangFunction) {
        println("${getIndent()}Function node: $node")
        super.visitFunction(node)
    }

    override fun visitCaseToken(node: ClangCaseToken) {
        println("${getIndent()}CaseToken node: $node")
        super.visitCaseToken(node)
    }

    override fun visitTypeToken(node: ClangTypeToken) {
        println("${getIndent()}TypeToken node: $node")
        super.visitTypeToken(node)
    }

    override fun visitLabelToken(node: ClangLabelToken) {
        println("${getIndent()}LabelToken node: $node")
        super.visitLabelToken(node)
    }

    override fun visitCommentToken(node: ClangCommentToken) {
        println("${getIndent()}CommentToken node: $node")
        super.visitCommentToken(node)
    }

    override fun visitFieldToken(node: ClangFieldToken) {
        println("${getIndent()}FieldToken node: $node")
        super.visitFieldToken(node)
    }

    override fun visitOpToken(node: ClangOpToken) {
        println("${getIndent()}OpToken node: $node")
        super.visitOpToken(node)
    }

    override fun visitVariableToken(node: ClangVariableToken) {
        println("${getIndent()}VariableToken node: $node")
        super.visitVariableToken(node)
    }

    override fun visitFuncNameToken(node: ClangFuncNameToken) {
        println("${getIndent()}FuncNameToken node: $node")
        super.visitFuncNameToken(node)
    }

//    override fun visitBreak(node: ClangBreak) {
//        println("${getIndent()}Break node: $node")
//        super.visitBreak(node)
//    }

//    override fun visitSyntaxToken(node: ClangSyntaxToken) {
//        println("${getIndent()}SyntaxToken node: $node")
//        super.visitSyntaxToken(node)
//    }

}


@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = GhidraApplePluginPackage.PKG_NAME,
    category = PluginCategoryNames.ANALYSIS,
    description = "",
    shortDescription = ""
)
class PrintASTPlugin(tool: PluginTool) : ProgramPlugin(tool) {

    init{
        createActions()
    }

    private fun createActions() {
        val action = object : DockingAction("My Action", name) {
            override fun actionPerformed(context: ActionContext?) {
                if (currentProgram != null) {
                    val dec = DecompiledFunctionProvider(currentProgram)
                    val function = currentProgram.functionManager.getFunctionAt(currentLocation.address)
                    val results = dec.getDecompiled(function)

                    val printer = TreePrinter()
                    printer.visit(results.cCodeMarkup)
                }
            }
        }

        action.menuBarData = MenuData(arrayOf("GhidraApple", "Print Function AST"))
        tool?.addAction(action)
    }
}

