package lol.fairplay.ghidraapple.analysis.objectivec

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Program
import lol.fairplay.ghidraapple.core.objc.encodings.EncodingLexer
import lol.fairplay.ghidraapple.core.objc.encodings.TypeEncodingParser
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode

class TypeResolver(val program: Program) {
    private val dtm = program.dataTypeManager

    fun parseEncoded(encodedType: String): DataType? {
        println("input: $encodedType")

        val result = TypeEncodingParser(EncodingLexer(encodedType)).parse()
        return buildParsed(result)
    }

    fun buildParsed(parsedType: TypeNode): DataType? {
        val builder = GhidraTypeBuilder(program)
        parsedType.accept(builder)

        return builder.getResult()
    }

    fun tryResolveDefinedStructPtr(name: String): DataType? {
        return PointerDataType(tryResolveDefinedStruct(name) ?: return null)
    }

    fun tryResolveDefinedStruct(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, name)
    }
}
