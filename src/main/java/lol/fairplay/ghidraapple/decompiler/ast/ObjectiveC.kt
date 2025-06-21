package lol.fairplay.ghidraapple.decompiler.ast

import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode

//
///**
// * [receiver selector:args]
// */
//class OCMethodCallExpression : Expression()
//
///**
// * obj.property
// */
//class OCPropertyAccessExpression : Expression()
//
///**
// * ^{ ... }
// */
//class OCBlockExpression : Expression()


sealed class OCExpression {

    data class MethodCall(
        val receiver: OCExpression,
        val selector: String,
        val arguments: List<OCExpression>,
    ) : OCExpression()

    data class PropertyAccess(
        val receiver: OCExpression,
        val propertyName: String,
        // isGetter...?
    ) : OCExpression()

    data class AllocationExpression(
        val className: String,
        val isInit: Boolean
    ) : OCExpression()

    data class Variable(
        val name: String,
        val type: TypeNode
    ): OCExpression()

    data class Literal(
        val value: Any,
    ) : OCExpression()

}


sealed class OCStatement {

}
