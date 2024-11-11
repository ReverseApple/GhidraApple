package lol.fairplay.ghidraapple.analysis.objectivec.modelling

import ghidra.program.model.address.GenericAddress
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.dataAt
import lol.fairplay.ghidraapple.analysis.utilities.tryResolveNamespace
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.get
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.longValue
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.deref
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignatureType
import lol.fairplay.ghidraapple.core.objc.encodings.EncodingLexer
import lol.fairplay.ghidraapple.core.objc.encodings.TypeEncodingParser
import lol.fairplay.ghidraapple.core.objc.encodings.parseEncodedProperty
import lol.fairplay.ghidraapple.core.objc.encodings.parseSignature


class StructureParsing(val program: Program) {

    val nsIvarList = tryResolveNamespace(program, "objc", "ivar_list_t")!!
    val nsPropList = tryResolveNamespace(program, "objc", "objc_property_list")!!
    val nsProtoList = tryResolveNamespace(program, "objc", "protocol_list_t")!!
    val nsMethodList = tryResolveNamespace(program, "objc", "method_list_t")!!
    val nsProtocol = tryResolveNamespace(program, "objc", "protocol_t")!!
    val nsClassRw = tryResolveNamespace(program, "objc", "class_rw_t")!!

    fun datResolve(address: Long, namespace: Namespace): Data? {
        val data = dataAt(program, program.address(address))
            ?: return null

        if (data.primarySymbol.parentNamespace.getName(true) == namespace.getName(true)) {
            return data
        } else {
            return null
        }
    }

    fun parseProtocolList(address: Long): List<OCProtocol>? {
        val struct = datResolve(address, nsProtoList) ?: return null
        val result = mutableListOf<OCProtocol>()

        for (i in 1 until struct.numComponents) {
            result.add(parseProtocol(struct[i].longValue(false))!!)
        }

        return result.toList()
    }

    fun parseProtocol(address: Long): OCProtocol? {
        val struct = datResolve(address, nsProtocol) ?: return null

        // I think only one of these are filled in at a time...?
        val instanceMethods = parseMethodList(struct[3].longValue(false))
        val classMethods = parseMethodList(struct[4].longValue(false))
        val optionalInstanceMethods = parseMethodList(struct[5].longValue(false))
        val optionalClassMethods = parseMethodList(struct[6].longValue(false))

        val methodListCoalesced = instanceMethods ?: classMethods ?: optionalInstanceMethods ?: optionalClassMethods

        val extendedSignatures = if (struct[9].longValue(false) != 0L) {
            val length = methodListCoalesced!!.size
            val result = mutableListOf<EncodedSignature>()
            val tblBase = struct[9].longValue(false)

            for (i in 0 until length) {
                val indexedAddress = program.address(tblBase + i * 8)
                val sigString = program.listing.getDataAt(indexedAddress).value as String

                result.add(parseSignature(sigString, EncodedSignatureType.METHOD_SIGNATURE))
            }

            result.toList()
        } else {
            null
        }

        return OCProtocol(
            name = struct[1].deref<String>(),
            protocols = parseProtocolList(struct[2].longValue(false)),
            instanceMethods = instanceMethods,
            classMethods = classMethods,
            optionalInstanceMethods = optionalInstanceMethods,
            optionalClassMethods = optionalClassMethods,
            instanceProperties = parsePropertyList(struct[7].longValue(false)),
            extendedSignatures = extendedSignatures
        )
    }



    fun parseProperty(dat: Data): OCProperty? {
        if (dat.dataType.name != "objc_property") return null

        val encoding = parseEncodedProperty(dat[1].deref<String>())

        return OCProperty(
            parent = TODO(),
            name = dat[0].deref<String>(),
            attributes = encoding.attributes,
            type = encoding.type,
            backingIvar = encoding.backingIvar
        )
    }

    fun parseIvar(dat: Data): OCIVar? {
        if (dat.dataType.name != "ivar_t") return null

        val parsedType = TypeEncodingParser(EncodingLexer(dat[2].deref<String>())).parse()

        return OCIVar(
            ocClass = TODO(),
            name = dat[1].deref<String>(),
            offset = dat[0].deref<Long>(),
            type = parsedType,
        )
    }

    fun parseClassRw(address: Long): OCClass? {
        val struct = datResolve(address, nsClassRw) ?: return null

        return OCClass(
            name = struct[3].deref<String>(),
            flags = struct[0].longValue(false),
            baseMethods = parseMethodList(struct[4].longValue(false)),
            baseProtocols = parseProtocolList(struct[5].longValue(false)),
            instanceVariables = parseIvarList(struct[6].longValue(false)),
            baseProperties = parsePropertyList(struct[8].longValue(false)),
            weakIvarLayout = struct[7].longValue(false),
        )
    }

    fun parseIvarList(address: Long): List<OCIVar>? {
        val struct = datResolve(address, nsIvarList) ?: return null
        val result = mutableListOf<OCIVar>()

        for (i in 2 until struct.numComponents) {
            result.add(parseIvar(struct[i])!!)
        }

        return result.toList()
    }

    fun parsePropertyList(address: Long): List<OCProperty>? {
        val struct = datResolve(address, nsPropList) ?: return null
        val result = mutableListOf<OCProperty>()

        for (i in 2 until struct.numComponents) {
            result.add(parseProperty(struct[i])!!)
        }

        return result.toList()
    }

    fun parseMethod(dat: Data): OCMethod? {
        if (dat.dataType.name != "method_t") {
            TODO()
        } else if (dat.dataType.name == "method_small_t") {
            TODO()
        } else {
            return null
        }
    }

    fun parseMethodList(address: Long): List<OCMethod>? {
        val struct = datResolve(address, nsMethodList)
        val result = mutableListOf<OCMethod>()
        TODO()
    }
}
