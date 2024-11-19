package lol.fairplay.ghidraapple.core.objc.encodings

import kotlin.test.Test

class TypeEncodingParserTest {

    @Test
    fun test_Parser() {
//        val example = "{Person=[50c]idf{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}]}"
//        val example = "{Employee=#if@{?=dd}(?=if)@^?@?}"
//        val example = "{?=\"\"(?=\"\"{?=\"red\"C\"green\"C\"blue\"C\"alpha\"C}\"channel\"[4C]\"value\"I)}"
        val example = "{z_stream_s=\"next_in\"*\"avail_in\"I\"total_in\"Q\"next_out\"*\"avail_out\"I\"total_out\"Q\"msg\"*\"state\"^{internal_state}\"zalloc\"^?\"zfree\"^?\"opaque\"^v\"data_type\"i\"adler\"Q\"reserved\"Q}"
//        val example = "{Person=[50c]b7b1df{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}](?=[50c][15c][30c])i}"
        val lexer = EncodingLexer(example)
        val parser = TypeEncodingParser(lexer)

        val result = parser.parse()

        println(result)
    }


    @Test
    fun test_ParseBulk() {
        val examples = listOf(
            "{z_stream_s=\"next_in\"*\"avail_in\"I\"total_in\"Q\"next_out\"*\"avail_out\"I\"total_out\"Q\"msg\"*\"state\"^{internal_state}\"zalloc\"^?\"zfree\"^?\"opaque\"^v\"data_type\"i\"adler\"Q\"reserved\"Q}",
            "{Person=[50c]b7b1df{Address=[50c][50c][20c]i}{Employment=[50c][50c]d}[5{Skill=[50c]i}](?=[50c][15c][30c])i}"
        )

        for (ex in examples) {
            val lexer = EncodingLexer(ex)
            val parser = TypeEncodingParser(lexer)
            val result = parser.parse()

            val jsonVisitor = JSONConversionVisitor()
            result.accept(jsonVisitor)
            println(jsonVisitor.getJSON()?.toString(2))
        }

    }

    @Test
    fun test_ParseSignature() {

        val examples = listOf(
            "B40@0:8@\"NSApplication\"16@\"NSUserActivity\"24@?<v@?@\"NSArray\">32"
                    to EncodedSignatureType.METHOD_SIGNATURE,
            "#16@0:8"
                    to EncodedSignatureType.METHOD_SIGNATURE,

            "@108@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16@48q56@64@72@80@88B96@100"
                    to EncodedSignatureType.METHOD_SIGNATURE,
            "v32@0:8@\"NSArray\"16@?<v@?@\"NSArray\"@\"NSArray\"d>24"
                    to EncodedSignatureType.METHOD_SIGNATURE,
            "@24@0:8:16"
                    to EncodedSignatureType.METHOD_SIGNATURE,
            "v40@?0I8^{__CFString=}12r^v20I28*32" to EncodedSignatureType.BLOCK_SIGNATURE,
        )

        for ((sig, type) in examples) {
            val lexer = EncodingLexer(sig)
            val parser = SignatureParser(lexer, type)
            val result = parser.parse()

            println(result)
        }
    }

    @Test
    fun test_ParseAttributeProperties() {
        val examples = listOf(
            "T@\"NSString\",C,N,V_contentUnavailableViewTitle",
            "T@\"NSString\",C,N,V_localizedCount",
            "T@\"NSString\",C,N,V_localizedSubtitle",
            "T@\"NSTimer\",&,V_cycleTimer",
            "T@\"NSString\",R,C,N",
            "T@\"<TAReceiptRequestDelegate>\",W,N,V_delegate",
            "T@\"NSString\",?,R,C"
        )

        for (ex in examples) {
            println("$ex \n        => ${parseEncodedProperty(ex)}")
        }
    }
}
