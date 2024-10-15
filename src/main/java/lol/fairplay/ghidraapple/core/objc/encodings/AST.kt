package lol.fairplay.ghidraapple.core.objc.encodings

sealed class TypeNode {
    data class Struct(val name: String?, val fields: List<Pair<String?, TypeNode>>) : TypeNode()
    data class ClassObject(val name: String?, val fields: List<Pair<String?, TypeNode>>) : TypeNode()
    data class Object(val name: String?) : TypeNode()
    data class Union(val name: String?, val fields: List<TypeNode>) : TypeNode()
    data class Array(val size: Int, val elementType: TypeNode) : TypeNode()
    data class Primitive(val type: String) : TypeNode()
    data class Pointer(val pointee: TypeNode) : TypeNode()
    data class Bitfield(val size: Int) : TypeNode()
}
