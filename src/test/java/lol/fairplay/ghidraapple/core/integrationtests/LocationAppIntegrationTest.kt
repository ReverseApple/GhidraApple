package lol.fairplay.ghidraapple.core.integrationtests

import org.junit.jupiter.api.Test
import resources.ResourceManager
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class LocationAppIntegrationTest : AbstractiOSAnalysisIntegrationTest() {
    @Test
    fun testTypeInferenceApp() {
        val program = setupProgramForBinary(ResourceManager.getResourceFile("LocationTestApp"))

        // Check that the methods are set up correctly
        val didUpdateLocationsAddress = program.addressFactory.defaultAddressSpace.getAddress(0x1000082a4)
        val didUpdateLocationsFunc = program.functionManager.getFunctionAt(didUpdateLocationsAddress)
        assertNotNull(didUpdateLocationsFunc, "Function not found")

        // Check that the protocol types and names were applied
        val r =
            listOf(
                "self" to "LocationHelper *",
                "selector" to "SEL",
                "locationManager" to "CLLocationManager *",
                "didUpdateLocations" to "NSArray *",
            )
        didUpdateLocationsFunc.parameters.forEachIndexed { index, param ->
            assertEquals(r[index].first, param.name)
            assertTrue("Parameter ${param.name} has wrong type: ${param.dataType.name}, expected ${r[index].second}") {
                param.dataType.name.startsWith(r[index].second)
            }
        }

        testTypeBound(
            program,
            // Type bound from an argument of an extended protocol method
            0x100008300 to "NSArray",
            0x100008534 to "CLLocation",
            // Receiver from a field of a struct
            0x1000079d0 to "CLLocationManager",
            0x100008324 to "LocationHelper",
        )

        testTypeBound(
            program,
            // Type bound from an argument of an extended protocol method
            0x100008300 to "NSArray",
            0x100008534 to "CLLocation",
            // Receiver from a field of a struct
            0x1000079d0 to "CLLocationManager",
            0x100008324 to "LocationHelper",
        )
    }
}
