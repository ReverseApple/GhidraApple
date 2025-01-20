package lol.fairplay.ghidraapple.core.objc.encodings

class TypeStringify : TypeNodeVisitor {
    private lateinit var result: String

    companion object {
        fun getResult(node: TypeNode): String {
            val vis = TypeStringify()
            node.accept(vis)
            return vis.result
        }

        private fun indent(str: String) = str.prependIndent("    ")
    }

    override fun visitStruct(struct: TypeNode.Struct) {
        val builder = StringBuilder()
        builder.append("struct ")

        if (struct.name != null) {
            builder.append(struct.name)
        }

        builder.append("{")

        if (struct.fields != null) {
            for ((name, node) in struct.fields) {
                builder.append("\n")
                val typeStr = getResult(node)

                var field =
                    if (name != null) {
                        "$typeStr $name"
                    } else {
                        typeStr
                    }

                if (node is TypeNode.Bitfield) {
                    field += " : ${node.size}"
                }

                builder.append("${indent(field)};")
            }
        }

        builder.append("\n}")
        result = builder.toString()
    }

    override fun visitClassObject(classObject: TypeNode.ClassObject) {
        result = "[${classObject.name} class]"
    }

    override fun visitObject(obj: TypeNode.Object) {
        result = obj.name?.let {
            "$it *"
        } ?: "id"
    }

    override fun visitUnion(union: TypeNode.Union) {
        val builder = StringBuilder()
        builder.append("union ")

        if (union.name != null) {
            builder.append(union.name)
        }

        builder.append("{")

        if (union.fields != null) {
            for ((name, node) in union.fields) {
                builder.append("\n")
                val typeStr = getResult(node)

                val field =
                    if (name != null) {
                        "$typeStr $name"
                    } else {
                        typeStr
                    }

                builder.append("${indent(field)};")
            }
        }

        builder.append("\n}")
        result = builder.toString()
    }

    override fun visitArray(array: TypeNode.Array) {
        val type = getResult(array.elementType)
        result = "$type [${array.size}]"
    }

    override fun visitPrimitive(primitive: TypeNode.Primitive) {
        result =
            when (primitive.type) {
                'c' -> "char" // this could also be `BOOL`
                'C' -> "unsigned char"
                's' -> "short"
                'S' -> "unsigned short"
                'i' -> "int"
                'I' -> "unsigned int"
                'l' -> "long"
                'L' -> "unsigned long"
                'q' -> "long long"
                'Q' -> "unsigned long long"
                'f' -> "float"
                'd' -> "double"
                'v' -> "void"
                'B' -> "bool"
                'D' -> "long double"
                '*' -> "char*"
                else -> throw Exception("Unknown primitive type: ${primitive.type}")
            }
    }

    override fun visitPointer(pointer: TypeNode.Pointer) {
        result = getResult(pointer.pointee) + "*"
    }

    override fun visitBitfield(bitfield: TypeNode.Bitfield) {
        result = "<BITFIELD:${bitfield.size}>"
    }

    override fun visitBlock(block: TypeNode.Block) {
        val builder = StringBuilder()

        if (block.returnType != null) {
            builder.append(getResult(block.returnType))
        }

        builder.append(" (^)(")

        if (block.parameters != null && block.parameters.isNotEmpty()) {
            block.parameters
                .joinToString(", ") { getResult(it.first) }
                .let { builder.append(it) }
        }

        builder.append(")")
        result = builder.toString()
    }

    override fun visitFunctionPointer(fnPtr: TypeNode.FunctionPointer) {
        result = "void*"
    }

    override fun visitSelector(selector: TypeNode.Selector) {
        result = "SEL"
    }
}
