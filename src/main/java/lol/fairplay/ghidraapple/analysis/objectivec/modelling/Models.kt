package lol.fairplay.ghidraapple.analysis.objectivec.modelling

import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.PropertyAttribute
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode

// TODO: we may be able to just move this to the core package.

open class OCFieldContainer

data class OCClass(
    val name: String,
    val flags: Long,
    val baseMethods: List<OCMethod>?,
    val baseProtocols: List<OCProtocol>?,
    val instanceVariables: List<OCIVar>?,
    val baseProperties: List<OCProperty>?,
    val weakIvarLayout: Long,
) : OCFieldContainer()

data class OCProtocol(
    val name: String,
    val protocols: List<OCProtocol>?,
    val instanceMethods: List<OCMethod>?,
    val classMethods: List<OCMethod>?,
    val optionalInstanceMethods: List<OCMethod>?,
    val optionalClassMethods: List<OCMethod>?,
    val instanceProperties: List<OCProperty>?,
    val extendedSignatures: List<EncodedSignature>?
) : OCFieldContainer()

data class OCMethod(
    val parent: OCFieldContainer,
    val name: String,
    private val signature: EncodedSignature,
    val implAddress: Long?,
) {

    fun getSignature(): EncodedSignature? {
        if (parent is OCProtocol) {
            // find the non-null method list, and then the index of ourselves in that list
            // then, if it's not null, access that index of `extendedSignatures` and return it.
        }
        // otherwise, return our field.
        return signature
    }

}

data class OCIVar(
    val ocClass: OCClass,
    val name: String,
    val offset: Long,
    val type: TypeNode,
)

data class OCProperty(
    val parent: OCFieldContainer,
    val name: String,
    val attributes: List<PropertyAttribute>,
    val type: TypeNode?,
    private val backingIvar: String?
) {
    fun getBackingIvar(): OCIVar? {
        return if (parent is OCClass) {
            parent.instanceVariables?.find { it.name == backingIvar }
        } else {
            null
        }
    }
}

