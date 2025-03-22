package lol.fairplay.ghidraapple.analysis.objectivec

import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.BooleanDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DoubleDataType
import ghidra.program.model.data.FloatDataType
import ghidra.program.model.data.LongDataType
import ghidra.program.model.data.LongDoubleDataType
import ghidra.program.model.data.LongLongDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.ShortDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.data.Union
import ghidra.program.model.data.UnionDataType
import ghidra.program.model.data.UnsignedCharDataType
import ghidra.program.model.data.UnsignedLongDataType
import ghidra.program.model.data.UnsignedLongLongDataType
import ghidra.program.model.data.UnsignedShortDataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.Program
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNodeVisitor
import java.security.SecureRandom

fun getRandomHexString(length: Int): String {
    val random = SecureRandom()
    val bytes = ByteArray(length / 2)
    random.nextBytes(bytes)

    return bytes.joinToString("") { "%02x".format(it) }
}

/**
 * Converts a ``TypeNode`` tree into a Ghidra ``DataType``
 */
class GhidraTypeBuilder(val program: Program) : TypeNodeVisitor {
    companion object {
        val OBJC_CLASS_CATEGORY = CategoryPath("/GA_OBJC")
    }

    private lateinit var result: DataType

    fun getResult(): DataType {
        return result
    }

    /**
     * Create a new instance of this class with the same parameters.
     *
     * This method is so that when we potentially change the constructor parameters, we won't
     * have to go and update each call.
     */
    fun extend(): GhidraTypeBuilder {
        return GhidraTypeBuilder(program)
    }

    fun getGAType(name: String): DataType? {
        return program.dataTypeManager.getDataType(OBJC_CLASS_CATEGORY, name)
    }

    fun createUnionDT(name: String): DataType {
        return program.dataTypeManager.addDataType(UnionDataType(OBJC_CLASS_CATEGORY, name), null)
    }

    fun createStructureDT(name: String): DataType {
        return program.dataTypeManager.addDataType(StructureDataType(OBJC_CLASS_CATEGORY, name, 0), null)
    }

    override fun visitModifiedType(modifiedType: TypeNode.ModifiedType) {
        modifiedType.baseType.accept(this)
    }

    override fun visitStruct(struct: TypeNode.Struct) {
        val name =
            (struct.name ?: "anon__${getRandomHexString(6)}").let {
                if (it.isEmpty()) "anon__${getRandomHexString(6)}" else it
            }

        var ghidraStruct = getGAType(name) as Structure?
        if (ghidraStruct != null) {
            result = ghidraStruct
            return
        }

        ghidraStruct = createStructureDT(name) as Structure
        if (struct.fields == null) {
            result = ghidraStruct
            return
        }

        for ((name, node) in struct.fields) {
            val visitor = extend()
            node.accept(visitor)
            val visitorResult = visitor.getResult()
            if (name != null) {
                ghidraStruct.add(visitorResult, visitorResult.length, name, null)
            } else {
                ghidraStruct.add(visitorResult, visitorResult.length)
            }
        }

        result = ghidraStruct
    }

    override fun visitClassObject(classObject: TypeNode.ClassObject) {
        result = program.dataTypeManager.getDataType("/_objc2_/CLASS")
    }

    override fun visitObject(obj: TypeNode.Object) {
        val idType = program.dataTypeManager.getDataType("/_objc2_/ID")

        if (obj.name == null) {
            result = idType
            return
        }

        val objDT = getGAType(obj.name) ?: createStructureDT(obj.name)
        result = PointerDataType(objDT, 8)
    }

    override fun visitUnion(union: TypeNode.Union) {
        val name =
            (union.name ?: "anon__${getRandomHexString(6)}").let {
                if (it.isEmpty()) "anon__${getRandomHexString(6)}" else it
            }

        var ghidraUnion = getGAType(name)
        if (ghidraUnion != null) {
            result = ghidraUnion
            return
        }

        ghidraUnion = createUnionDT(name) as Union
        if (union.fields == null) {
            result = ghidraUnion
            return
        }

        for ((name, node) in union.fields) {
            val visitor = extend()
            node.accept(visitor)
            val visitorResult = visitor.getResult()

            if (name != null) {
                ghidraUnion.add(visitorResult, visitorResult.length, name, null)
            } else {
                ghidraUnion.add(visitor.getResult(), visitorResult.length)
            }
        }

        result = ghidraUnion
    }

    override fun visitArray(array: TypeNode.Array) {
        val visitor = extend()
        array.elementType.accept(visitor)

        result = ArrayDataType(visitor.getResult(), array.size)
    }

    override fun visitPrimitive(primitive: TypeNode.Primitive) {
        result =
            when (primitive.type) {
                'c' -> CharDataType.dataType // this could also be `BOOL`
                'C' -> UnsignedCharDataType.dataType
                's' -> ShortDataType.dataType
                'S' -> UnsignedShortDataType.dataType
//            'i' -> IntegerDataType.dataType
//            'I' -> UnsignedIntegerDataType.dataType
                'i', 'I' -> Undefined4DataType.dataType
                'l' -> LongDataType.dataType
                'L' -> UnsignedLongDataType.dataType
                'q' -> LongLongDataType.dataType
                'Q' -> UnsignedLongLongDataType.dataType
                'f' -> FloatDataType.dataType
                'd' -> DoubleDataType.dataType
                'v' -> VoidDataType.dataType
                'B' -> BooleanDataType.dataType
                'D' -> LongDoubleDataType.dataType
                '*' -> PointerDataType(CharDataType.dataType, 8)
                else -> throw Exception("Unknown primitive type: ${primitive.type}")
            }
    }

    override fun visitPointer(pointer: TypeNode.Pointer) {
        val visitor = extend()
        pointer.pointee.accept(visitor)

        result = PointerDataType(visitor.getResult(), 8)
    }

    override fun visitBitfield(bitfield: TypeNode.Bitfield) {
        throw NotImplementedError("Bitfield type reconstruction is not implemented yet.")
    }

    override fun visitBlock(block: TypeNode.Block) {
        result = program.dataTypeManager.getDataType("/_objc2_/ID")
    }

    override fun visitFunctionPointer(fnPtr: TypeNode.FunctionPointer) {
        result = PointerDataType(VoidDataType.dataType, 8)
    }

    override fun visitSelector(fnPtr: TypeNode.Selector) {
        result = program.dataTypeManager.getDataType("/_objc2_/SEL")
    }
}
