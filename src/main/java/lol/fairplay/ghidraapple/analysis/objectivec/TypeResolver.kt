package lol.fairplay.ghidraapple.analysis.objectivec

import ghidra.program.model.data.*
import ghidra.program.model.data.BooleanDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
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

    fun tryResolveTypedef(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, name)
    }

    fun tryResolveDefinedStruct(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, "struct_${name}")
    }

}
