package lol.fairplay.ghidraapple.core.objc.encodings

sealed class TypeNode {
    abstract fun accept(visitor: TypeNodeVisitor)

    data class ModifiedType(
        val baseType: TypeNode,
        val modifier: Char,
    ) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitModifiedType(this)
        }
    }

    data class Struct(val name: String?, val fields: List<Pair<String?, TypeNode>>?) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitStruct(this)
        }
    }

    data class ClassObject(val name: String?, val fields: List<Pair<String?, TypeNode>>?) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitClassObject(this)
        }
    }

    data class Object(val name: String?) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitObject(this)
        }
    }

    data class Union(val name: String?, val fields: List<Pair<String?, TypeNode>>?) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitUnion(this)
        }
    }

    data class Array(val size: Int, val elementType: TypeNode) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitArray(this)
        }
    }

    data class Primitive(val type: Char) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitPrimitive(this)
        }
    }

    object Selector : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitSelector(this)
        }
    }

    data class Pointer(val pointee: TypeNode) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitPointer(this)
        }
    }

    data class Bitfield(val size: Int) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitBitfield(this)
        }
    }

    data class Block(val returnType: TypeNode?, val parameters: List<Pair<TypeNode, Int?>>?) : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitBlock(this)
        }
    }

    object FunctionPointer : TypeNode() {
        override fun accept(visitor: TypeNodeVisitor) {
            visitor.visitFunctionPointer(this)
        }
    }
}

interface TypeNodeVisitor {
    fun visitModifiedType(modifiedType: TypeNode.ModifiedType)

    fun visitStruct(struct: TypeNode.Struct)

    fun visitClassObject(classObject: TypeNode.ClassObject)

    fun visitObject(obj: TypeNode.Object)

    fun visitUnion(union: TypeNode.Union)

    fun visitArray(array: TypeNode.Array)

    fun visitPrimitive(primitive: TypeNode.Primitive)

    fun visitPointer(pointer: TypeNode.Pointer)

    fun visitBitfield(bitfield: TypeNode.Bitfield)

    fun visitBlock(block: TypeNode.Block)

    fun visitFunctionPointer(fnPtr: TypeNode.FunctionPointer)

    fun visitSelector(selector: TypeNode.Selector)
}
