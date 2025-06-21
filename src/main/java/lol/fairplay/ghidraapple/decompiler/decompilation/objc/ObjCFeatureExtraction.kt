package lol.fairplay.ghidraapple.decompiler.decompilation.objc

import ghidra.program.model.pcode.PcodeOpAST
import lol.fairplay.ghidraapple.decompiler.ast.OCExpression
import lol.fairplay.ghidraapple.decompiler.core.Context

class ObjCFeatureExtraction(
    private val context: Context
) {

    fun resolveMethodCall(call: PcodeOpAST): OCExpression.MethodCall {
        TODO()
    }

}
