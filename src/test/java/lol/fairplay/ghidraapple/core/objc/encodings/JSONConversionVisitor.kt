package lol.fairplay.ghidraapple.core.objc.encodings

import org.json.JSONArray
import org.json.JSONObject


class JSONConversionVisitor : TypeNodeVisitor {

    private var result: JSONObject? = null

    fun getJSON(): JSONObject? {
        return result
    }

    fun extend(): JSONConversionVisitor {
        return JSONConversionVisitor()
    }

    override fun visitStruct(struct: TypeNode.Struct) {
        val json = JSONObject()
        json.put("type", "Struct")
        json.put("name", struct.name)

        if (struct.fields != null) {
            val arr = JSONArray()
            for ((name, node) in struct.fields) {
                val entry = JSONObject()
                val visitor = extend()
                node.accept(visitor)
                entry.put("name", name)
                entry.put("value", visitor.getJSON())
                arr.put(entry)
            }
            json.put("fields", arr)
        }

        result = json
    }

    override fun visitClassObject(classObject: TypeNode.ClassObject) {
        val json = JSONObject()
        json.put("type", "ClassObject")
        json.put("name", classObject.name)

        if (classObject.fields != null) {
            val arr = JSONArray()
            for ((name, node) in classObject.fields) {
                val entry = JSONObject()
                val visitor = extend()
                node.accept(visitor)
                entry.put("name", name)
                entry.put("value", visitor.getJSON())
                arr.put(entry)
            }
            json.put("fields", arr)
        }

        result = json
    }

    override fun visitObject(obj: TypeNode.Object) {
        val json = JSONObject()
        json.put("type", "Object")
        json.put("name", obj.name)
        result = json
    }

    override fun visitUnion(union: TypeNode.Union) {
        val json = JSONObject()
        json.put("type", "Union")
        json.put("name", union.name)

        if (union.fields != null) {
            val arr = JSONArray()
            for ((name, node) in union.fields) {
                val entry = JSONObject()
                val visitor = extend()
                node.accept(visitor)
                entry.put("name", name)
                entry.put("value", visitor.getJSON())
                arr.put(entry)
            }
            json.put("fields", arr)
        }

        result = json
    }

    override fun visitArray(array: TypeNode.Array) {
        val json = JSONObject()
        json.put("type", "Array")

        val elementJson = let{
            val visitor = extend()
            array.elementType.accept(visitor)
            visitor.getJSON()
        }
        json.put("elementType", elementJson)
        json.put("size", array.size)

        result = json
    }

    override fun visitPrimitive(primitive: TypeNode.Primitive) {
        val json = JSONObject()
        json.put("type", "Primitive")
        json.put("code", primitive.type)
        result = json
    }

    override fun visitPointer(pointer: TypeNode.Pointer) {
        val json = JSONObject()
        json.put("type", "Pointer")
        val pointeeJson = let{
            val visitor = extend()
            pointer.pointee.accept(visitor)
            visitor.getJSON()
        }
        json.put("pointee", pointeeJson)
        result = json
    }

    override fun visitBitfield(bitfield: TypeNode.Bitfield) {
        val json = JSONObject()
        json.put("type", "Bitfield")
        json.put("size", bitfield.size)
        result = json
    }

    override fun visitBlock(block: TypeNode.Block) {
        val json = JSONObject()
        json.put("type", "Block")
        result = json
    }

    override fun visitFunctionPointer(fnPtr: TypeNode.FunctionPointer) {
        val json = JSONObject()
        json.put("type", "FunctionPointer")
        result = json
    }

    override fun visitSelector(fnPtr: TypeNode.Selector) {
        val json = JSONObject()
        json.put("type", "Selector")
        result = json
    }

}