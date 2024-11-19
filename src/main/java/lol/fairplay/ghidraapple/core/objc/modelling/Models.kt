package lol.fairplay.ghidraapple.core.objc.modelling

import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.PropertyAttribute
import lol.fairplay.ghidraapple.core.objc.encodings.SignatureTypeModifier
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode


open class OCFieldContainer

data class OCClass(
    val name: String,
    val flags: Long,
    val superclass: OCClass?,
    var baseMethods: List<OCMethod>?,
    var baseProtocols: List<OCProtocol>?,
    var instanceVariables: List<OCIVar>?,
    var baseProperties: List<OCProperty>?,
    val weakIvarLayout: Long,
) : OCFieldContainer() {

    fun getInheritance(): List<OCClass>? {
        if (superclass == null) {
            return null
        }
        val superInheritance = superclass.getInheritance()
        return if (superInheritance != null) {
            listOf(superclass) + superInheritance
        } else {
            listOf(superclass)
        }
    }

    fun getProperties(): List<OCProperty>? {
        // aggregate all baseProperties and properties from protocols.
        val props = baseProperties?.toMutableList() ?: return null
        baseProtocols?.forEach {
            it.instanceProperties?.let { props.addAll(it) }
        }
        return props.toList()
    }

    fun getCollapsedProperties(): List<OCProperty>? {
        val inheritance = getInheritance()
        println("inheritance: $inheritance")
        val myProperties = getProperties()
        if (inheritance == null) {
            return myProperties
        }

        val startMap = myProperties?.associate { it.name to it }
            ?.toMutableMap() ?: return null

        inheritance.forEach {
            it.baseProperties?.forEach { prop ->
                if (!startMap.containsKey(prop.name)) {
                    startMap[prop.name] = prop
                }
            }
        }

        return startMap.values.toList()
    }

}

data class OCProtocol(
    val name: String,
    var protocols: List<OCProtocol>?,
    var instanceMethods: List<OCMethod>?,
    var classMethods: List<OCMethod>?,
    var optionalInstanceMethods: List<OCMethod>?,
    var optionalClassMethods: List<OCMethod>?,
    var instanceProperties: List<OCProperty>?,
    var extendedSignatures: List<EncodedSignature>?
) : OCFieldContainer()

data class OCMethod(
    val parent: OCFieldContainer,
    val name: String,
    val isInstanceMethod: Boolean = true,
    private val signature: EncodedSignature,
    val implAddress: Long?,
) {

    override fun toString(): String {
        return "OCMethod(name='$name', signature=$signature, implAddress=$implAddress)"
//        return prototypeString()
    }

    fun getSignature(): EncodedSignature? {
        if (parent is OCProtocol && parent.extendedSignatures != null) {
            // find the non-null method list, and then the index of ourselves in that list
            // then, if it's not null, access that index of `extendedSignatures` and return it.

            val methods = parent.instanceMethods
                ?: parent.classMethods
                ?: parent.optionalInstanceMethods
                ?: parent.optionalClassMethods
                ?: return signature
            val index = methods.indexOf(this)

            return parent.extendedSignatures!!.getOrNull(index) ?: signature
        }
        // otherwise, return our field.
        return signature
    }

    /**
     * Get the method prototype in Objective-C syntax.
     */
    fun prototypeString(): String {
        // todo: (low priority) decouple this method from OCMethod for separation of concern.

        val sig = getSignature() ?: return ""

        val prefix = if (isInstanceMethod) "-" else "+"
        val returnType = sig.returnType.first ?: return ""

        if (sig.parameters.count() > 0) {
            var nsplit = name.split(":").filter { it.trim().isNotEmpty() }
            println(nsplit)
            var result = "$prefix($returnType)$name:${sig.parameters.first().first}\""
            for (i in 1 until sig.parameters.count()) {
                result += " ${nsplit[i]}\$:(${sig.parameters[i].first})"
            }
            return "$result;"
        } else {
            return "$prefix($returnType)$name;"
        }
    }

}

data class OCIVar(
    val ocClass: OCClass,
    val name: String,
    val offset: Int,
    val type: TypeNode,
    val alignment: Int,
    val size: Int,
) {
    override fun toString(): String {
        return "OCIVar(name='$name', offset=$offset, type=$type)"
    }
}

data class OCProperty(
    val parent: OCFieldContainer,
    val name: String,
    val attributes: List<PropertyAttribute>,
    val type: Pair<TypeNode, List<SignatureTypeModifier>?>?,
    private val backingIvar: String?
) {

    override fun toString(): String {
        return "OCProperty(name='$name', attributes=$attributes, type=$type)"
    }

    fun getBackingIvar(): OCIVar? {
        return if (parent is OCClass) {
            parent.instanceVariables?.find { it.name == backingIvar }
        } else {
            null
        }
    }
}

