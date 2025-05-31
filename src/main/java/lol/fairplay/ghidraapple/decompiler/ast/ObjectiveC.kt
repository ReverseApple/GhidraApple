package lol.fairplay.ghidraapple.decompiler.ast

/**
 * [receiver selector:args]
 */
class OCMethodCallExpression : Expression()

/**
 * obj.property
 */
class OCPropertyAccessExpression : Expression()

/**
 * ^{ ... }
 */
class OCBlockExpression : Expression()

