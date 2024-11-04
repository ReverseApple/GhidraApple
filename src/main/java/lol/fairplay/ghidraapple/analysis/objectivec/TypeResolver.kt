package lol.fairplay.ghidraapple.analysis.objectivec

import ghidra.program.model.data.*
import ghidra.program.model.data.BooleanDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Program

class TypeResolver(val program: Program) {

    private val dtm = program.dataTypeManager

    private fun getPrimitive(type: Char): DataType? {
        return when (type) {
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
            else -> null
        }
    }

    @Deprecated("Use GhidraTypeBuilder instead.")
    fun parseEncoded(encodedType: String): DataType? {
        // this will be more robust in the future.
        // reference: https://nshipster.com/type-encodings/

        println("input: $encodedType")

        when (encodedType[0]) {
            '@' -> {
                if (encodedType.length == 1)
                    return dtm.getDataType("/_objc2_/ID")
                // expect a defined type structure
                return tryResolveTypedef(encodedType.substring(2, encodedType.length - 1))
            }
            '^' -> {
                val inside = parseEncoded(encodedType.substring(1)) ?: return null
                return PointerDataType(inside)
            }
            '*' -> return PointerDataType(dtm.getDataType("/char"))
            // not going to support arrays/structures/whatnot for now.
            else -> {
                val primitive = getPrimitive(encodedType[0]) ?: return null
                return primitive
            }
        }

    }

    fun tryResolveTypedef(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, name)
    }

    fun tryResolveDefinedStruct(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, "struct_${name}")
    }

}
