package lol.fairplay.ghidraapple.core.objc.encodings


enum class EncodedSignatureType {
    METHOD_SIGNATURE,
    BLOCK_SIGNATURE,
}

enum class SignatureTypeModifier(val code: Char) {
    CONST('r'),
    IN('n'),
    IN_OUT('N'),
    OUT('o'),
    BY_COPY('O'),
    BY_REF('R'),
    ONE_WAY('V');

    companion object {
        fun fromCode(code: Char): SignatureTypeModifier? {
            return SignatureTypeModifier.entries.find {it.code == code}
        }
    }
}

data class EncodedSignature(
    val signatureType: EncodedSignatureType,
    val returnType: Pair<TypeNode, List<SignatureTypeModifier>?>,
    val stackSize: Int,
    val parameters: List<Triple<TypeNode, Int, List<SignatureTypeModifier>?>>
)
