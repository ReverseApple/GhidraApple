import org.junit.jupiter.api.Test
import resources.ResourceManager

class TestTypeInferenceApp : AbstractiOSAnalysisIntegrationTest() {
    @Test
    fun testTypeInferenceApp() {
        val program = setupProgramForBinary(ResourceManager.getResourceFile("TypeInferenceTestApp"))

        testSelectors(
            program,
            0x1000093f0 to "init",
            0x100008024 to "viewDidLoad",
        )

        testStaticReceivers(
            program,
            0x10000847c to "NSArray",
            0x100008528 to "NSMutableArray",
            0x1000085c8 to "NSMutableArray",
            0x10000866c to "NSMutableArray",
            0x100008740 to "NSMutableArray",
            0x100008828 to "NSMutableArray",
            0x100008968 to "NSMutableArray",
            0x100008b08 to "NSMutableArray",
            0x100008cb8 to "NSMutableArray",
            0x100008ea4 to "NSMutableArray",
            0x10000904c to "NSMutableArray",
            0x10000911c to "NSMutableArray",
        )
    }
}
