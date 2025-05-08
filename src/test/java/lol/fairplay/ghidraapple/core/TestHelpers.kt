package lol.fairplay.ghidraapple.core

import lol.fairplay.ghidraapple.analysis.utilities.parameterNamesForMethod
import org.junit.jupiter.api.Test

class TestHelpers {
    @Test
    fun testParameters() {
        val params = parameterNamesForMethod("foo:bar:")
        assert(params == listOf("foo", "bar"))
    }

    @Test
    fun testNoParams() {
        val params = parameterNamesForMethod("foo")
        assert(params == listOf<String>())
    }

    @Test
    fun testConstructorSelector() {
        val params = parameterNamesForMethod("initWithSomeType:")
        assert(params == listOf("someType"))
    }
    @Test
    fun testConstructorWithMultipleParams() {
        val params = parameterNamesForMethod("initWithURL:append:")
        assert(params == listOf("uRL", "append"))
    }

}

