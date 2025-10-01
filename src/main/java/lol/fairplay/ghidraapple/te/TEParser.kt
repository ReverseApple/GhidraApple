package lol.fairplay.ghidraapple.te

import ghidra.app.services.DataTypeQueryService
import ghidra.app.util.parser.FunctionSignatureParser
import ghidra.framework.plugintool.PluginTool
import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.data.BooleanDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.EnumDataType
import ghidra.program.model.data.FileDataTypeManager
import ghidra.program.model.data.Float16DataType
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.TypedefDataType
import ghidra.program.model.data.UnionDataType
import ghidra.program.model.data.VoidDataType
import ghidra.util.data.DataTypeParser
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass
import lol.fairplay.ghidraapple.analysis.objectivec.blocks.BlockLayoutDataType
import java.io.File

@Serializable
data class TETypeInfo(
    val declID: String?,
    val typeName: String,
)

@Serializable
data class TENameAndTypeInfo(
    val name: String,
    val type: TETypeInfo,
)

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("kind")
sealed interface TETypeProperties

@Serializable
@SerialName("Typedef")
data class TETypeDefTypeProperties(
    val underlyingType: TETypeInfo,
) : TETypeProperties

@Serializable
data class TEStructField(
    val offset: Long,
    val size: Long,
    val type: TETypeInfo,
)

@Serializable
data class TENameAndStructField(
    val name: String,
    val field: TEStructField,
)

@Serializable
@SerialName("Struct")
data class TEStructTypeProperties(
    val fields: List<TENameAndStructField>,
) : TETypeProperties

@Serializable
@SerialName("Union")
data class TEUnionTypeProperties(
    val members: List<TENameAndTypeInfo>,
) : TETypeProperties

@Serializable
data class TEEnumEntry(
    val name: String,
    val value: ULong,
)

@Serializable
@SerialName("Enum")
data class TEEnumTypeProperties(
    val backingType: TETypeInfo,
    val entries: List<TEEnumEntry>,
) : TETypeProperties

@Serializable
@SerialName("Function")
data class TEFunctionTypeProperties(
    val returnType: TETypeInfo,
    val params: List<TENameAndTypeInfo>,
) : TETypeProperties

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class TEEmittedType(
    val type: TETypeInfo,
    val properties: TETypeProperties,
    val pseudoRoot: String,
    val location: List<String>,
)

private typealias TEDataTypeResolverResult = Pair<DataType?, Boolean>

class TEParser(
    tool: PluginTool,
    dtmFile: File,
) {
    val dtm: FileDataTypeManager =
        FileDataTypeManager.createFileArchive(dtmFile)

    fun addDataType(dt: DataType) {
        this.dtm.withTransaction<Exception>("add ${dt.name} data type") {
            this.dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER)
        }
    }

    val json =
        Json {
            serializersModule =
                SerializersModule {
                    polymorphic(TETypeProperties::class) {
                        subclass(TETypeDefTypeProperties::class)
                        subclass(TEStructTypeProperties::class)
                        subclass(TEUnionTypeProperties::class)
                        subclass(TEEnumTypeProperties::class)
                        subclass(TEFunctionTypeProperties::class)
                    }
                }
        }

    val dtMap = mutableMapOf<String, DataType>()

    val dtParser =
        DataTypeParser(
            dtm,
            dtm,
            tool.getService(DataTypeQueryService::class.java),
            DataTypeParser.AllowedDataTypes.ALL,
        )
    val funSigParser =
        FunctionSignatureParser(
            dtm,
            tool.getService(DataTypeQueryService::class.java),
        )

    private fun ghidraParsableTypeString(typeString: String) =
        typeString
            .replace(Regex("(?<![0-9A-z_])const\\s?"), "")
            .replace(Regex("\\s?struct\\s"), "")
            .replace(Regex("\\s?enum\\s"), "")
            .replace(Regex("\\s?union\\s"), "")
            .replace(Regex("\\s?volatile\\s?"), "")
            .replace(Regex("\\s_Nullable\\s?"), "")
            .replace(Regex("\\s_Nonnull\\s?"), "")
            .replace(Regex("\\s_Null_unspecified\\s?"), "")
            .replace(Regex("(?<![0-9A-z_])_Bool(?![0-9a-z_])"), "bool")

    fun getDefaultDataType(typeInfo: TETypeInfo): DataType {
        // If none of the above worked, return the default data type.
        println("Returning default data type for DeclID ${typeInfo.declID} with name ${typeInfo.typeName}.")
        return DataType.DEFAULT
    }

    fun matchInDTM(typeName: String): DataType? {
        val matchingTypes =
            this.dtm.allDataTypes
                .asSequence()
                .filter { it.name == typeName }
                .toList()
        return if (matchingTypes.size == 1) {
            matchingTypes.first()
        } else if (matchingTypes.size > 1) {
            // Return the latest matching type.
            matchingTypes.maxByOrNull { it.lastChangeTime }!!
        } else {
            null
        }
    }

    fun resolveDataType(
        typeInfo: TETypeInfo,
        nameForFunction: String? = null,
    ): DataType {
        // HACK: This is an Objective-C object type name. We don't support those yet.
        if (typeInfo.typeName.matches(Regex("[0-9A-z_]+<[0-9A-z_]+> \\*"))) {
            return PointerDataType(VoidDataType())
        }
        // HACK: This is a C++ type name. We need to use something that Ghidra will understand.
        if (typeInfo.typeName == "decltype(nullptr)") return PointerDataType(VoidDataType())
        // HACK: Ghidra doesn't understand `_Bool`, so we need to catch this manually.
        if (typeInfo.typeName == "_Bool") return BooleanDataType()
        // This is an Objective-C block type. Let's parse it as a regular function then convert back.
        if (typeInfo.typeName.contains("(^")) {
            val functionSignatureTextWithFunctionName =
                // Convert it to a regular function signature.
                ghidraParsableTypeString(typeInfo.typeName.replace("(^", "(*"))
                    .replace(Regex("\\s?__bsearch_noescape\\s?"), "")
                    .replace(Regex("\\s?__sort_noescape\\s?"), "")
                    .replace(
                        Regex("\\(\\*\\)"),
                        "$nameForFunction",
                    )
            try {
                this.funSigParser
                    .parse(
                        null,
                        functionSignatureTextWithFunctionName,
                    )?.let { funcDefType ->
                        val blockDataType =
                            BlockLayoutDataType(
                                this.dtm,
                                nameForFunction,
                                nameForFunction,
                                funcDefType.returnType,
                                funcDefType.arguments
                                    .map { it as ParameterDefinitionImpl }
                                    .toTypedArray(),
                            )
                        return PointerDataType(blockDataType, this.dtm)
                    }
            } catch (t: Throwable) {
                println("Failed to parse block-converted function signature text $functionSignatureTextWithFunctionName: $t")
                return getDefaultDataType(typeInfo)
            }
        }
        // HACK: Ghidra doesn't know what a `__builtin_va_list` is.
        if (typeInfo.typeName == "__builtin_va_list") {
            // It seems that, on most modern systems, this is a char *.
            return PointerDataType(CharDataType())
        }
        // HACK: Ghidra uses a non-standard name for `_Float16`, so we have to catch it manually.
        if (typeInfo.typeName == "_Float16") {
            return Float16DataType()
        }
        // First check the map.
        dtMap[typeInfo.declID]?.let { return it }
        // Next check if it may be a function pointer.
        if (typeInfo.typeName.contains("(*")) {
            var funPtrCount = 1
            val functionSignatureTextWithFunctionName =
                ghidraParsableTypeString(typeInfo.typeName)
                    .replace(
                        Regex("\\(\\*\\)"),
                        "$nameForFunction",
                    )
                    // Replace "<type> *func(...)" syntax with "<type>* func(...)" syntax.
                    .replace(Regex("^([0-9A-z_]+)(\\s\\*)(?=[0-9A-z_]+\\()"), "$1* ")
            try {
                this.funSigParser
                    .parse(
                        null,
                        functionSignatureTextWithFunctionName,
                    )?.let { return PointerDataType(it, this.dtm) }
            } catch (t: Throwable) {
                println("Failed to parse function signature text $functionSignatureTextWithFunctionName: $t")
                return getDefaultDataType(typeInfo)
            }
        }
        // Next try parsing it as a primitive.
        DataTypeUtilities
            .getCPrimitiveDataType(typeInfo.typeName)
            ?.let { return it }
        // Next check if it's in the DataTypeManager.
        this
            .matchInDTM(
                ghidraParsableTypeString(typeInfo.typeName),
            )?.let { return it }
        // Next check if the pointed data type is in the DataTypeManager.
        if (typeInfo.typeName.endsWith(" *")) {
            val pointerlessTypeName =
                ghidraParsableTypeString(typeInfo.typeName).let {
                    it.substring(
                        0,
                        it.length - 2,
                    )
                }
            this.matchInDTM(pointerlessTypeName)?.let {
                return PointerDataType(it, this.dtm)
            }
            // HACK: This is a bit presumptuous, but if we can't find it in the DTM, just pretend it's a void *.
            return PointerDataType(VoidDataType())
        }
        // Finally try fully parsing it.
        try {
            val parseableTypeString =
                ghidraParsableTypeString(typeInfo.typeName)
            this.dtParser
                .parse(parseableTypeString)
                ?.let { return it }
        } catch (t: Throwable) {
            println("Failed to parse type name ${typeInfo.typeName}: $t")
            return getDefaultDataType(typeInfo)
        }
        return getDefaultDataType(typeInfo)
    }

    fun parseEmittedTypes(types: List<String>) {
        types.forEach {
            try {
                parseEmittedType(it)
            } catch (t: Throwable) {
            }
        }
        this.dtm.save()
    }

    fun parseEmittedType(typeJSON: String) {
        val parsedType = json.decodeFromString<TEEmittedType>(typeJSON)
        val parsedTypeCategoryPath =
            CategoryPath(
                CategoryPath("/${parsedType.pseudoRoot}"),
                parsedType.location,
            )
        when (parsedType.properties) {
            is TETypeDefTypeProperties -> {
                val resolvedUnderlyingType =
                    this.resolveDataType(
                        parsedType.properties.underlyingType,
                        parsedType.type.typeName + "_func",
                    )
                // C allows typedef's to have the same name as the underlying type. Ghidra does not (at least
                //  not in the same category). We add the conventional "_t" in these cases to avoid conflict.
                val shouldUseSafeSuffix =
                    (resolvedUnderlyingType.name == parsedType.type.typeName) &&
                        resolvedUnderlyingType.categoryPath == parsedTypeCategoryPath
                val safeTypeName = "${parsedType.type.typeName}${if (shouldUseSafeSuffix) "_t" else ""}"
                val typedefDT =
                    TypedefDataType(parsedTypeCategoryPath, safeTypeName, resolvedUnderlyingType, this.dtm)
                this.dtMap[parsedType.type.declID!!] = typedefDT
                this.addDataType(typedefDT)
            }

            is TEStructTypeProperties -> {
                val typeName =
                    parsedType.type.typeName.ifEmpty {
                        "anonymous_struct_${parsedType.type.declID!!}"
                    }
                val structType =
                    StructureDataType(
                        parsedTypeCategoryPath,
                        typeName,
                        0,
                        this.dtm,
                    )
                parsedType.properties.fields.forEach { field ->
                    val resolvedDataType =
                        this.resolveDataType(field.field.type, field.name)
                    structType.insertAtOffset(
                        (field.field.offset / 8).toInt(),
                        resolvedDataType,
                        (field.field.size / 8).toInt(),
                        field.name,
                        "",
                    )
                }
                this.dtMap[parsedType.type.declID!!] = structType
                this.addDataType(structType)
            }

            is TEUnionTypeProperties -> {
                val typeName =
                    parsedType.type.typeName.ifEmpty {
                        "anonymous_union_${parsedType.type.declID!!}"
                    }
                val unionDataType = UnionDataType(parsedTypeCategoryPath, typeName, this.dtm)
                parsedType.properties.members.forEach { (memberName, typeInfo) ->
                    unionDataType.add(
                        this.resolveDataType(typeInfo, memberName),
                        -1,
                        memberName,
                        "",
                    )
                }
                this.dtMap[parsedType.type.declID!!] = unionDataType
                this.addDataType(unionDataType)
            }

            is TEEnumTypeProperties -> {
                val resolvedBackingType = this.resolveDataType(parsedType.properties.backingType)
                val enumDT =
                    EnumDataType(
                        parsedTypeCategoryPath,
                        parsedType.type.typeName.ifEmpty { "anonymous_enum_${parsedType.type.declID!!}" },
                        resolvedBackingType.length,
                        this.dtm,
                    )
                parsedType.properties.entries.forEach { enumDT.add(it.name, it.value.toLong()) }
                parsedType.type.declID?.let { this.dtMap[it] = enumDT }
                this.addDataType(enumDT)
            }

            is TEFunctionTypeProperties -> {
                val funcDefType =
                    FunctionDefinitionDataType(parsedTypeCategoryPath, parsedType.type.typeName, this.dtm)
                funcDefType.returnType =
                    this.resolveDataType(
                        parsedType.properties.returnType,
                        parsedType.type.typeName + "_return",
                    )
                val paramDefs = mutableListOf<ParameterDefinitionImpl>()
                parsedType.properties.params.forEachIndexed { index, param ->
                    val safeFunctionName = "${parsedType.type.typeName}_param_${param.name.ifEmpty { index + 1 }}"
                    val paramDT = resolveDataType(param.type, safeFunctionName)
                    param.type.declID?.let { this.dtMap[it] = paramDT }
                    paramDefs.add(
                        ParameterDefinitionImpl(
                            param.name,
                            paramDT,
                            "",
                        ),
                    )
                }
                funcDefType.setArguments(*paramDefs.toTypedArray())
                this.dtMap[parsedType.type.declID!!] = funcDefType
                this.addDataType(funcDefType)
            }
        }
    }
}
