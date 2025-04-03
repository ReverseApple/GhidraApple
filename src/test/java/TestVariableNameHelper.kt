import lol.fairplay.ghidraapple.analysis.utilities.getSuggestedVariableNameForSelectorResult
import kotlin.test.Ignore

@Ignore("Not Implemented yet")
class TestVariableNameHelper {


    val basicExamples = listOf(
        "requestWithMultipartFormRequest:writingStreamContentsToFile:completionHandler:" to "request",
        "HTTPBodyStream" to "httpBodyStream",
        "setWithSet" to "set",
        "pinnedCertificates" to "pinnedCertificates",
        "setWithCapacity:" to "set",
        "checkResourceIsReachableAndReturnError:" to "check", // Maybe also something like 'checkResult'?
        "attributesOfItemAtPath:error:" to "attributes"

    )

    fun test() {
        for ((selector, expected) in basicExamples) {
            val result = getSuggestedVariableNameForSelectorResult(selector)
            assert(result == expected) {
                "Expected $expected but got $result for selector $selector"
            }
        }
    }


    fun testMutableCopy() {
        assert(getSuggestedVariableNameForSelectorResult("mutableCopy", "multipartFormRequest") == "copyOfMultipartFormRequest")
    }

    fun testInitWith(){
        assert(getSuggestedVariableNameForSelectorResult("initWithURL:append:", recvTypeName = "NSOutputStream") == "outputStream")
    }
}
