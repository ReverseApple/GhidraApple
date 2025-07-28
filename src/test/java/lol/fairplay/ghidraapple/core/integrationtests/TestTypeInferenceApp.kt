package lol.fairplay.ghidraapple.core.integrationtests

import org.junit.jupiter.api.Test
import resources.ResourceManager

class TestTypeInferenceApp : AbstractiOSAnalysisIntegrationTest() {
    @Test
    fun testTypeInferenceApp() {
        val program = setupProgramForBinary(ResourceManager.getResourceFile("TestApplicationTypeInference"))

        testSelectors(
            program,
            0x100008034 to "viewDidLoad",
        )

        testIntraAllocs(
            program,
            0x10000815c to "UISceneConfiguration",
            0x100008f04 to "Human",
            0x100008f54 to "Animal",
            0x100008fa4 to "Cat",
            0x100008ff4 to "Dog",
            0x100009044 to "Horse",
            0x100009094 to "Accommodation",
        )

//        assertEquals(listOf("foo", "bar"), listOf("foo", "baz"))
    }
}
