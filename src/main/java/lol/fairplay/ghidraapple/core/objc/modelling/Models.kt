package lol.fairplay.ghidraapple.core.objc.modelling

import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.PropertyAttribute
import lol.fairplay.ghidraapple.core.objc.encodings.SignatureTypeModifier
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode
import lol.fairplay.ghidraapple.core.objc.encodings.TypeStringify

open class OCFieldContainer(open val name: String)

abstract class OCField(open val name: String) {
    abstract fun parent(): OCFieldContainer
}

open class ResolvedEntity<T : OCField>(val name: String, initial: T? = null) {
    // stack order is concrete to abstract
    internal val stack = mutableListOf<T>()

    fun chain(): List<Pair<OCFieldContainer, T>> = stack.map { it.parent() to it }

    fun concrete(): T = stack[0]

    fun abstract(): List<T> = if (stack.size != 1) stack.subList(1, stack.size) else listOf(stack[0])

    protected fun pushConcrete(t: T) = stack.add(0, t)

    internal fun pushAbstract(t: T) = stack.add(t)

    init {
        initial?.let {
            pushConcrete(it)
        }
    }

    internal fun append(other: ResolvedEntity<T>) {
        other.stack.forEach { pushAbstract(it) }
    }

    override fun toString(): String {
        return "ResolvedEntity(name='$name', stack=$stack)"
    }
}

class ResolvedMethod(name: String, initial: OCMethod? = null) : ResolvedEntity<OCMethod>(name, initial) {
    fun bestSignature(): Pair<EncodedSignature?, OCFieldContainer> {
        val impl =
            stack.find {
                it.parent is OCProtocol && (it.parent as OCProtocol).extendedSignatures != null
            } ?: stack.first()
        return impl.getSignature() to impl.parent
    }
}

class ResolvedProperty(name: String, initial: OCProperty? = null) : ResolvedEntity<OCProperty>(name, initial)

data class OCClass(
    override val name: String,
    val flags: ULong,
    val superclass: OCClass?,
    var baseClassMethods: List<OCMethod>?,
    var baseInstanceMethods: List<OCMethod>?,
    var baseProtocols: List<OCProtocol>?,
    var instanceVariables: List<OCIVar>?,
    var baseClassProperties: List<OCProperty>?,
    var baseInstanceProperties: List<OCProperty>?,
    val weakIvarLayout: Long,
) : OCFieldContainer(name) {
    /**
     * Returns the list of superclasses from concrete to abstract.
     */
    fun getInheritance(): List<OCClass> {
        return if (superclass == null) {
            listOf()
        } else {
            listOf(superclass) + superclass.getInheritance()
        }
    }

    fun isSwift(): Boolean = (flags and ClassFlags.IS_SWIFT.bit) != 0uL

    fun resolvedProperties(): List<ResolvedProperty> {
        // Initialize resolution mapping with the most concrete forms relative to this class.
        val propertyMapping =
            baseProperties().associate {
                it.name to ResolvedProperty(it.name, it)
            }.toMutableMap()

        // Then, obtain resolutions for protocol methods, and append to ours.
        baseProtocols?.forEach { protocol ->
            protocol.resolvedProperties().forEach { propResolution ->
                if (propertyMapping[propResolution.name] == null) {
                    propertyMapping[propResolution.name] = propResolution
                } else {
                    propertyMapping[propResolution.name]!!.append(propResolution)
                }
            }
        }

        // Leverage the inheritance path graph to further augment the resolutions.
        superclass?.resolvedProperties()?.forEach { propResolution ->
            if (propertyMapping[propResolution.name] == null) {
                propertyMapping[propResolution.name] = propResolution
            } else {
                propertyMapping[propResolution.name]!!.append(propResolution)
            }
        }

        return propertyMapping.values.toList()
    }

    fun resolvedMethods(): List<ResolvedMethod> {
        val methodMapping =
            baseMethods().associate {
                it.name to ResolvedMethod(it.name, it)
            }.toMutableMap()

        // collect resolved methods from implemented protocols
        baseProtocols?.forEach { protocol ->
            protocol.resolvedMethods().forEach { methodResolution ->
                if (methodMapping[methodResolution.name] == null) {
                    methodMapping[methodResolution.name] = methodResolution
                } else {
                    methodMapping[methodResolution.name]!!.append(methodResolution)
                }
            }
        }

        superclass?.resolvedMethods()?.forEach { methodResolution ->
            if (methodMapping[methodResolution.name] == null) {
                methodMapping[methodResolution.name] = methodResolution
            } else {
                methodMapping[methodResolution.name]!!.append(methodResolution)
            }
        }

        return methodMapping.values.toList()
    }

    fun baseMethods(): List<OCMethod> {
        return (baseInstanceMethods ?: listOf()) + (baseClassMethods ?: listOf())
    }

    fun baseProperties(): List<OCProperty> {
        return (baseInstanceProperties ?: listOf()) + (baseClassProperties ?: listOf())
    }

    fun getImplementationForSelector(selector: String): OCMethod? {
        return resolvedMethods().find { it.name == selector }?.concrete()
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
//    var classProperties: List<OCProperty>?,
    var extendedSignatures: List<EncodedSignature>?,
) : OCFieldContainer(name) {
    fun resolvedProperties(): List<ResolvedProperty> {
        val propertyMapping =
            instanceProperties?.associate {
                it.name to ResolvedProperty(it.name, it)
            }.orEmpty().toMutableMap()

        protocols?.forEach { protocol ->
            protocol.resolvedProperties().forEach { propResolution ->
                if (propertyMapping[propResolution.name] == null) {
                    propertyMapping[propResolution.name] = propResolution
                } else {
                    propertyMapping[propResolution.name]!!.append(propResolution)
                }
            }
        }

        return propertyMapping.values.toList()
    }

    fun resolvedMethods(): List<ResolvedMethod> {
        val methodMapping =
            baseMethods().associate {
                it.name to ResolvedMethod(it.name, it)
            }.toMutableMap()

        protocols?.forEach { protocol ->
            protocol.resolvedMethods().forEach { methodResolution ->
                if (methodMapping[methodResolution.name] == null) {
                    methodMapping[methodResolution.name] = methodResolution
                } else {
                    methodMapping[methodResolution.name]!!.append(methodResolution)
                }
            }
        }

        return methodMapping.values.toList()
    }

    fun baseMethods(): List<OCMethod> {
// //         fixme: I believe this function was devised in a misconception that only one of these
// //          fields could be non-null per instance.
        return (instanceMethods ?: listOf()) +
            (classMethods ?: listOf()) +
            (optionalInstanceMethods ?: listOf()) +
            (optionalClassMethods ?: listOf())
    }
}

data class OCMethod(
    var parent: OCFieldContainer,
    override val name: String,
    private val signature: EncodedSignature,
    val implAddress: Long?,
) : OCField(name) {
    override fun parent(): OCFieldContainer = parent

    override fun toString(): String {
        return "OCMethod(name='$name', signature=${getSignature()}, implAddress=$implAddress)"
    }

    fun isClassMethod(): Boolean {
        return if (parent is OCClass) {
            (parent as OCClass).baseClassMethods?.contains(this) == true
        } else {
            val cond1 = (parent as OCProtocol).classMethods?.contains(this) == true
            val cond2 = (parent as OCProtocol).optionalClassMethods?.contains(this) == true

            cond1 || cond2
        }
    }

    fun getSignature(): EncodedSignature? {
        if (parent is OCProtocol && (parent as OCProtocol).extendedSignatures != null) {
            val protoParent = parent as OCProtocol

            // find the non-null method list, and then the index of ourselves in that list
            // then, if it's not null, access that index of `extendedSignatures` and return it.
            // use the activeMethodList instead of resolvedInstanceMethods because we are operating on the
            // presumption that only local methods will have entries in the extended signatures
            val methods = protoParent.baseMethods()
            val index = methods.indexOf(this)

            return protoParent.extendedSignatures!!.getOrNull(index) ?: signature
        }
        // otherwise, return our field.
        return signature
    }

    /**
     * Get the method prototype in Objective-C syntax.
     */
    fun prototypeString(): String {
        val sig = getSignature() ?: return ""

        val prefix = if (isClassMethod()) "+" else "-"
        val returnType = TypeStringify.getResult(sig.returnType.first)

        if (sig.parameters.count() > 0) {
            val nsplit = name.split(":").filter { it.trim().isNotEmpty() }
            var result = "$prefix($returnType)${nsplit[0]}:(${TypeStringify.getResult(sig.parameters.first().first)})"

            if (nsplit.size != sig.parameters.count()) {
                return result
            }
            for (i in 1 until sig.parameters.count()) {
                val typeStr = TypeStringify.getResult(sig.parameters[i].first)
                result += " ${nsplit[i]}:($typeStr)"
            }

            return "$result;"
        } else {
            return "$prefix($returnType)$name;"
        }
    }
}

data class OCIVar(
    val ocClass: OCClass,
    override val name: String,
    val offset: Int,
    val type: TypeNode?,
    val alignment: Int,
    val size: Int,
) : OCField(name) {
    override fun parent(): OCFieldContainer = ocClass

    override fun toString(): String {
        return "OCIVar(name='$name', offset=$offset, type=$type)"
    }
}

data class OCProperty(
    var parent: OCFieldContainer,
    override val name: String,
    val attributes: List<PropertyAttribute>,
    val type: Pair<TypeNode, List<SignatureTypeModifier>?>?,
    val customGetter: String?,
    val customSetter: String?,
    private val backingIvar: String?,
) : OCField(name) {
    override fun parent(): OCFieldContainer = parent

    override fun toString(): String {
        return "OCProperty(name='$name', attributes=$attributes, type=$type)"
    }

    fun isClassProperty(): Boolean {
        return if (parent is OCClass) {
            (parent as OCClass).baseClassProperties?.contains(this) == true
        } else {
            false
        }
    }

    fun declaration(): String {
        val builder = StringBuilder()
        builder.append("@property ")

        if (attributes.filterNot { it == PropertyAttribute.TYPE_ENCODING }.isNotEmpty()) {
            builder.append("(")
            attributes
                .mapNotNull { it.annotationString() }
                .let {
                    if (isClassProperty()) {
                        it + "class"
                    } else {
                        it
                    }
                }.map {
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
            (parent as OCClass).instanceVariables?.find { it.name == backingIvar }
        } else {
            null
        }
    }
}
