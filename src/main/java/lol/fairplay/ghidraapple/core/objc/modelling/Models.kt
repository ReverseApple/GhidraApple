package lol.fairplay.ghidraapple.core.objc.modelling

import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.PropertyAttribute
import lol.fairplay.ghidraapple.core.objc.encodings.SignatureTypeModifier
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode
import lol.fairplay.ghidraapple.core.objc.encodings.TypeStringify


open class OCFieldContainer(open val name: String)


// fixme: this whole class is probably overkill
class ResolvedMethod(val name: String) {

    // stack order is concrete to abstract
    private val stack = mutableListOf<OCMethod>()

    fun method(): OCMethod = stack[0]
    fun pushInstance(method: OCMethod) = stack.add(method)

    fun bestSignature(): Pair<EncodedSignature?, OCFieldContainer> {
        val impl = stack.find {
            it.parent is OCProtocol && it.parent.extendedSignatures != null
        } ?: stack.first()
        return impl.getSignature() to impl.parent
    }
}


data class OCClass(
    override val name: String,
    val flags: Long,
    val superclass: OCClass?,
    var baseMethods: List<OCMethod>?,
    var baseProtocols: List<OCProtocol>?,
    var instanceVariables: List<OCIVar>?,
    var baseProperties: List<OCProperty>?,
    val weakIvarLayout: Long,
) : OCFieldContainer(name) {

    /**
     * Returns the list of superclasses from concrete to abstract.
     */
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

    fun resolvedProperties(): List<OCProperty>? {
        val inheritance = getInheritance()?.reversed()
        val propertyMapping = mutableMapOf<String, OCProperty>()

        inheritance?.forEach {
            it.baseProperties?.forEach { prop ->
                propertyMapping[prop.name] = prop
            }
        }

        baseProtocols?.forEach {
            it.resolvedProperties()?.forEach { prop ->
                propertyMapping[prop.name] = prop
            }
        }

        baseProperties?.forEach { prop ->
            propertyMapping[prop.name] = prop
        }

        return propertyMapping.values.toList()
    }

    fun resolvedMethods(): List<ResolvedMethod>? {
        val inheritance = getInheritance()?.reversed()
        val methodMapping = baseMethods?.associate {
            val a = ResolvedMethod(it.name)
            a.pushInstance(it)
            it.name to a
        }?.toMutableMap() ?: mutableMapOf()

        // collect resolved methods from implemented protocols
        baseProtocols?.forEach {
            it.resolvedMethods()?.forEach { method ->
                if (method.name !in methodMapping) {
                    methodMapping[method.name] = ResolvedMethod(method.name)
                }

                methodMapping[method.name]!!.pushInstance(method)
            }
        }

        // collect methods using MRO
        inheritance?.forEach {
            it.baseMethods?.forEach { method ->
                if (method.name !in methodMapping) {
                    methodMapping[method.name] = ResolvedMethod(method.name)
                }

                methodMapping[method.name]!!.pushInstance(method)
            }
        }

        return if (methodMapping.isEmpty()) {
            null
        } else {
            methodMapping.values.toList()
        }
    }

}

data class OCProtocol(
    override val name: String,
    var protocols: List<OCProtocol>?,
    var instanceMethods: List<OCMethod>?,
    var classMethods: List<OCMethod>?,
    var optionalInstanceMethods: List<OCMethod>?,
    var optionalClassMethods: List<OCMethod>?,
    var instanceProperties: List<OCProperty>?,
    var extendedSignatures: List<EncodedSignature>?
) : OCFieldContainer(name) {

    fun resolvedProperties(): List<OCProperty>? {
        val propertyMapping = mutableMapOf<String, OCProperty>()

        protocols?.forEach {
            it.resolvedProperties()?.forEach { prop ->
                propertyMapping[prop.name] = prop
            }
        }

        instanceProperties?.forEach { prop ->
            propertyMapping[prop.name] = prop
        }

        return if (propertyMapping.isEmpty()) {
            null
        } else {
            propertyMapping.values.toList()
        }
    }

    fun resolvedMethods(): List<OCMethod>? {
        val methodMapping = mutableMapOf<String, OCMethod>()

        protocols?.forEach {
            it.resolvedMethods()?.forEach { method ->
                methodMapping[method.name] = method
            }
        }

        activeMethodList()?.forEach { method ->
            methodMapping[method.name] = method
        }

        return if (methodMapping.isEmpty()) {
            null
        } else {
            methodMapping.values.toList()
        }
    }

    fun activeMethodList(): List<OCMethod>? {
        return instanceMethods ?: classMethods ?: optionalInstanceMethods ?: optionalClassMethods
    }

}

data class OCMethod(
    val parent: OCFieldContainer,
    val name: String,
    val isInstanceMethod: Boolean = true,
    private val signature: EncodedSignature,
    val implAddress: Long?,
) {

    override fun toString(): String {
        return "OCMethod(name='$name', signature=${getSignature()}, implAddress=$implAddress)"
    }

    fun getSignature(): EncodedSignature? {
        if (parent is OCProtocol && parent.extendedSignatures != null) {
            // find the non-null method list, and then the index of ourselves in that list
            // then, if it's not null, access that index of `extendedSignatures` and return it.

            // use the activeMethodList instead of resolvedMethods because we are operating on the
            // presumption that only local methods will have entries in the extended signatures
            val methods = parent.activeMethodList() ?: return signature
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
    val customGetter: String?,
    val customSetter: String?,
    private val backingIvar: String?
) {

    override fun toString(): String {
        return "OCProperty(name='$name', attributes=$attributes, type=$type)"
    }

    fun declaration(): String {
        val builder = StringBuilder()
        builder.append("\n")
        builder.append("@property ")

        if (attributes.filterNot { it == PropertyAttribute.TYPE_ENCODING }.isNotEmpty()) {
            builder.append("(")
            attributes
                .mapNotNull { it.annotationString() }
                .map {
                    when (it) {
                        "getter=" -> "getter=$customGetter"
                        "setter=" -> "setter=$customSetter"
                        else -> it
                    }
                }
                .joinToString(", ", postfix = ") ") { it }
                .let { builder.append(it) }
        }
        val typeString = TypeStringify.getResult(type!!.first)
        builder.append("$typeString $name;")
        builder.append("\n")

        return builder.toString()
    }

    fun getBackingIvar(): OCIVar? {
        return if (parent is OCClass) {
            parent.instanceVariables?.find { it.name == backingIvar }
        } else {
            null
        }
    }
}



