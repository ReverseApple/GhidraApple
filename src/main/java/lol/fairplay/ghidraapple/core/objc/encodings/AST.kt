package lol.fairplay.ghidraapple.core.objc.encodings

sealed class TypeNode {
    data class Struct(val name: String?, val fields: List<Pair<String?, TypeNode>>) : TypeNode()
    data class Array(val size: Int, val elementType: TypeNode) : TypeNode()
    data class Primitive(val type: String) : TypeNode()
}
