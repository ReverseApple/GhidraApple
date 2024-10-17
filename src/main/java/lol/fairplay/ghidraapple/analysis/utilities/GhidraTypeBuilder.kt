package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.BitFieldDataType
import ghidra.program.model.data.BooleanDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DoubleDataType
import ghidra.program.model.data.FloatDataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.LongDataType
import ghidra.program.model.data.LongLongDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.ShortDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.UnionDataType
import ghidra.program.model.data.UnsignedCharDataType
import ghidra.program.model.data.UnsignedIntegerDataType
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

    private lateinit var result: DataType

    fun getResult(): DataType {
        return result
    }

    fun tryResolveTypedef(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, name)
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

    fun tryResolveDefinedStruct(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, "struct_${name}")
    }

    override fun visitStruct(struct: TypeNode.Struct) {
        val name = (struct.name ?: "anon__${getRandomHexString(6)}").let{
            if (it.isEmpty()) "anon__${getRandomHexString(6)}" else it
        }

        val ghidraStruct = (tryResolveDefinedStruct(name) ?: StructureDataType(name, 0)) as StructureDataType

        if (struct.fields == null) {
            result = ghidraStruct
            return
        }

        for ((name, node) in struct.fields) {
            val visitor = extend()
            node.accept(visitor)

            if (name != null) {
                ghidraStruct.add(visitor.getResult(), name, null)
            } else {
                ghidraStruct.add(visitor.getResult())
            }
        }

        result = ghidraStruct
    }

    override fun visitClassObject(classObject: TypeNode.ClassObject) {
        throw Exception("Not sure.")
    }

    override fun visitObject(obj: TypeNode.Object) {
        if (obj.name == null) {
            throw Exception("Not sure.")
        }

        val resolved = tryResolveTypedef(obj.name)
        result = resolved ?: program.dataTypeManager.getDataType("/_objc2_/ID")
    }

    override fun visitUnion(union: TypeNode.Union) {

        val name = (union.name ?: "anon__${getRandomHexString(6)}").let{
            if (it.isEmpty()) "anon__${getRandomHexString(6)}" else it
        }

        val ghidraUnion = UnionDataType(name)

        if (union.fields == null) {
            result = ghidraUnion
            return
        }

        for ((name, node) in union.fields) {
            val visitor = extend()
            node.accept(visitor)

            if (name != null) {
                ghidraUnion.add(visitor.getResult(), name, null)
            } else {
                ghidraUnion.add(visitor.getResult())
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
        result = when (primitive.type) {
            'c' -> CharDataType.dataType // this could also be `BOOL`
            'C' -> UnsignedCharDataType.dataType
            's' -> ShortDataType.dataType
            'S' -> UnsignedShortDataType.dataType
            'i' -> IntegerDataType.dataType
            'I' -> UnsignedIntegerDataType.dataType
            'l' -> LongDataType.dataType
            'L' -> UnsignedLongDataType.dataType
            'q' -> LongLongDataType.dataType
            'Q' -> UnsignedLongLongDataType.dataType
            'f' -> FloatDataType.dataType
            'd' -> DoubleDataType.dataType
            'v' -> VoidDataType.dataType
            'B' -> BooleanDataType.dataType
            '*' -> PointerDataType(CharDataType.dataType)
            else -> throw Exception("Unknown primitive type: ${primitive.type}")
        }
    }

    override fun visitPointer(pointer: TypeNode.Pointer) {
        val visitor = extend()
        pointer.pointee.accept(visitor)

        result = PointerDataType(visitor.getResult())
    }

    override fun visitBitfield(bitfield: TypeNode.Bitfield) {
        throw Exception("Not sure.")
    }

    override fun visitBlock(block: TypeNode.Block) {
        result = program.dataTypeManager.getDataType("/_objc2_/ID")
    }

    override fun visitFunctionPointer(fnPtr: TypeNode.FunctionPointer) {
        result = PointerDataType(VoidDataType.dataType)
    }
}
