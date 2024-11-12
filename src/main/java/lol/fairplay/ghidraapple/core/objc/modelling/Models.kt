package lol.fairplay.ghidraapple.core.objc.modelling

import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.PropertyAttribute
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode


open class OCFieldContainer

data class OCClass(
    val name: String,
    val flags: Long,
    var baseMethods: List<OCMethod>?,
    var baseProtocols: List<OCProtocol>?,
    var instanceVariables: List<OCIVar>?,
    var baseProperties: List<OCProperty>?,
    val weakIvarLayout: Long,
) : OCFieldContainer()

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

