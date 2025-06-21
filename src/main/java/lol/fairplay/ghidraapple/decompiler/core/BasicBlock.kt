package lol.fairplay.ghidraapple.decompiler.core

import ghidra.program.model.pcode.PcodeBlockBasic
import ghidra.program.model.pcode.PcodeOpAST
import lol.fairplay.ghidraapple.decompiler.ast.Statement

class BasicBlock(
    val pcodeBlock: PcodeBlockBasic,
) {
    val successors: MutableList<BasicBlock> = mutableListOf()
    val predecessors: MutableList<BasicBlock> = mutableListOf()

    private val statements: MutableList<Statement> = mutableListOf()
    private val pcodeMap: MutableMap<Statement, PcodeOpAST> = mutableMapOf()

    fun pushStatement(stmt: Statement, pcode: PcodeOpAST) {
        statements.add(stmt)
        pcodeMap[stmt] = pcode
    }
}
