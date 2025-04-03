package lol.fairplay.ghidraapple.analysis.objectivec.modelling

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.deref
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.derefUntyped
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.get
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.longValue
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.dataAt
import lol.fairplay.ghidraapple.analysis.utilities.tryResolveNamespace
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignatureType
import lol.fairplay.ghidraapple.core.objc.encodings.EncodingLexer
import lol.fairplay.ghidraapple.core.objc.encodings.TypeEncodingParser
import lol.fairplay.ghidraapple.core.objc.encodings.parseEncodedProperty
import lol.fairplay.ghidraapple.core.objc.encodings.parseSignature
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass
import lol.fairplay.ghidraapple.core.objc.modelling.OCFieldContainer
import lol.fairplay.ghidraapple.core.objc.modelling.OCIVar
import lol.fairplay.ghidraapple.core.objc.modelling.OCMethod
import lol.fairplay.ghidraapple.core.objc.modelling.OCProperty
import lol.fairplay.ghidraapple.core.objc.modelling.OCProtocol

class StructureParsing(
    val program: Program,
) {
    val nsIvarList = tryResolveNamespace(program, "objc", "ivar_list_t")
    val nsPropList = tryResolveNamespace(program, "objc", "objc_property_list")
    val nsProtoList = tryResolveNamespace(program, "objc", "protocol_list_t")
    val nsMethodList = tryResolveNamespace(program, "objc", "method_list_t")
    val nsProtocol = tryResolveNamespace(program, "objc", "protocol_t")
    val nsClass = tryResolveNamespace(program, "objc", "class_t")

    private val parentStack = mutableListOf<OCFieldContainer>()

    fun datResolve(
        address: Long,
        namespace: Namespace,
    ): Data? {
        val data =
            dataAt(program, program.address(address))
                ?: return null

        if (data.primarySymbol == null) {
            return null
        }

        if (data.primarySymbol.parentNamespace.getName(true) == namespace.getName(true)) {
            return data
        } else {
            return null
        }
    }

    fun parseProtocolList(address: Long): List<OCProtocol>? {
        val struct = datResolve(address, nsProtoList ?: return null) ?: return null
        val result = mutableListOf<OCProtocol>()

        for (i in 1 until struct.numComponents) {
            result.add(parseProtocol(struct[i].longValue(false))!!)
        }

        return result.toList()
    }

    fun parseProtocol(address: Long): OCProtocol? {
        val struct = datResolve(address, nsProtocol ?: return null) ?: return null

        val protocol =
            OCProtocol(
                name = struct[1].deref<String>(),
                protocols = parseProtocolList(struct[2].longValue(false)),
                instanceMethods = null,
                classMethods = null,
                optionalInstanceMethods = null,
                optionalClassMethods = null,
                instanceProperties = null,
                extendedSignatures = null,
            )

        parentStack.add(protocol)
        val instanceProperties = parsePropertyList(struct[7].longValue(false))

        // I think only one of these are filled in at a time...?
        val instanceMethods = parseMethodList(struct[3].longValue(false))
        val classMethods = parseMethodList(struct[4].longValue(false))
        val optionalInstanceMethods = parseMethodList(struct[5].longValue(false))
        val optionalClassMethods = parseMethodList(struct[6].longValue(false))

        val methodListCoalesced = instanceMethods ?: classMethods ?: optionalInstanceMethods ?: optionalClassMethods

        val extendedSignatures =
            if (struct[9].longValue(false) != 0L) {
                val length = methodListCoalesced!!.size
                val result = mutableListOf<EncodedSignature>()
                val tblBase = struct[9].longValue(false)

                for (i in 0 until length) {
                    val indexedAddress = program.address(tblBase + i * 8)
                    val sigAddr = program.listing.getDataAt(indexedAddress).getLong(0)
                    val sigString = program.listing.getDataAt(program.address(sigAddr)).value as String
                    result.add(parseSignature(sigString, EncodedSignatureType.METHOD_SIGNATURE))
                }

                result.toList()
            } else {
                null
            }

        protocol.extendedSignatures = extendedSignatures
        protocol.instanceMethods = instanceMethods
        protocol.classMethods = classMethods
        protocol.optionalInstanceMethods = optionalInstanceMethods
        protocol.optionalClassMethods = optionalClassMethods
        protocol.instanceProperties = instanceProperties
        parentStack.removeLast()

        return protocol
    }

    fun parseProperty(dat: Data): OCProperty? {
        if (dat.dataType.name != "objc_property") return null

        val encoding = parseEncodedProperty(dat[1].deref<String>())

        return OCProperty(
            parent = parentStack.last(),
            name = dat[0].deref<String>(),
            attributes = encoding.attributes,
            type = encoding.type,
            customGetter = encoding.customGetter,
            customSetter = encoding.customSetter,
            backingIvar = encoding.backingIvar,
        )
    }

    fun parseIvar(dat: Data): OCIVar? {
        if (dat.dataType.name != "ivar_t") return null

        val parsedType = TypeEncodingParser(EncodingLexer(dat[2].deref<String>())).parse()

        return OCIVar(
            ocClass = parentStack.last() as OCClass,
            offset = dat[0].derefUntyped().getInt(0),
            name = dat[1].deref<String>(),
            type = parsedType,
            alignment = dat[3].longValue().toInt(),
            size = dat[4].longValue().toInt(),
        )
    }

    fun parseClass(address: Address, isMetaclass: Boolean = false): OCClass? {
        return parseClass(address.offset, isMetaclass)
    }

    fun parseClass(
        address: Long,
        isMetaclass: Boolean = false,
    ): OCClass? {
        val klassRo = datResolve(address, nsClass ?: return null) ?: return null

        // get the class_t->data (class_rw_t *) field...
        val rwStruct = klassRo[4].derefUntyped(tolerant = true)
        val superAddress = klassRo[1].longValue(false)

        val klass =
            OCClass(
                name = rwStruct[3].deref<String>(),
                flags = rwStruct[0].longValue(false).toULong(),
                superclass = parseClass(superAddress),
                baseClassMethods = null,
                baseInstanceMethods = null,
                baseProtocols = null,
                instanceVariables = null,
                baseClassProperties = null,
                baseInstanceProperties = null,
                weakIvarLayout = rwStruct[7].longValue(false),
            )

        // Parse regular stuff.
        if (!isMetaclass) {
            parentStack.add(klass)
        }

        // Parse the metaclass field only if we are not a metaclass.
        val metaclass =
            if (!isMetaclass) {
                parseClass(klassRo[0].longValue(false), isMetaclass = true)
            } else {
                null
            }

        klass.baseClassMethods = metaclass?.baseInstanceMethods
        klass.baseClassProperties = metaclass?.baseInstanceProperties

        klass.baseInstanceMethods = parseMethodList(rwStruct[4].longValue(false))
        klass.baseProtocols = parseProtocolList(rwStruct[5].longValue(false))
        klass.instanceVariables = parseIvarList(rwStruct[6].longValue(false))
        klass.baseInstanceProperties = parsePropertyList(rwStruct[8].longValue(false))

        if (!isMetaclass) {
            parentStack.removeLast()
        }

//        // add class-members to our baseProtocols
//        klass.baseProtocols?.forEach { baseProtocol ->
//            metaclass?.baseProtocols?.find { mp -> mp.name == baseProtocol.name }?.let { metaProtocol ->
//                baseProtocol.classMethods
//            }
//        }

        return klass
    }

    fun parseIvarList(address: Long): List<OCIVar>? {
        val struct = datResolve(address, nsIvarList ?: return null) ?: return null
        val result = mutableListOf<OCIVar>()

        for (i in 2 until struct.numComponents) {
            result.add(parseIvar(struct[i])!!)
        }

        return result.toList()
    }

    fun parsePropertyList(address: Long): List<OCProperty>? {
        val struct = datResolve(address, nsPropList ?: return null) ?: return null
        val result = mutableListOf<OCProperty>()

        for (i in 2 until struct.numComponents) {
            result.add(parseProperty(struct[i])!!)
        }

        return result.toList()
    }

    fun parseMethod(dat: Data): OCMethod? {
        if (dat.dataType.name == "method_t") {
            return OCMethod(
                parent = parentStack.last(),
                name = dat[0].deref<String>(),
                signature = parseSignature(dat[1].deref<String>(), EncodedSignatureType.METHOD_SIGNATURE),
                implAddress = dat[2].longValue(false),
            )
        } else if (dat.dataType.name == "method_small_t") {
            val addresses =
                (0 until dat.numComponents).map {
                    dat[it].getPrimaryReference(0).toAddress
                }

            val name = dataAt(program, addresses[0])!!.deref<String>()
            val signature =
                parseSignature(
                    dataAt(program, addresses[1])?.value as String,
                    EncodedSignatureType.METHOD_SIGNATURE,
                )
            val implementation = addresses[2]

            val parent = parentStack.last()

            return OCMethod(
                parent = parent,
                name = name,
                signature = signature,
                implAddress = implementation.unsignedOffset,
            )
        } else {
            return null
        }
    }

    fun parseMethodList(address: Long): List<OCMethod>? {
        val struct = datResolve(address, nsMethodList ?: return null) ?: return null
        val result = mutableListOf<OCMethod>()
        for (i in 2 until struct.numComponents) {
            result.add(parseMethod(struct[i])!!)
        }
        return result.toList()
    }
}
