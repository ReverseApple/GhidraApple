package lol.fairplay.ghidraapple.core.objc.encodings


enum class EncodedSignatureType {
    METHOD_SIGNATURE,
    BLOCK_SIGNATURE,
}

data class EncodedSignature(
    val signatureType: EncodedSignatureType,
    val returnType: TypeNode,
    val stackSize: Int,
    val parameters: List<Pair<TypeNode, Int>>
)
