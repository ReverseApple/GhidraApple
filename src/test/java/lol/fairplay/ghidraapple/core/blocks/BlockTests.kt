package lol.fairplay.ghidraapple.core.blocks

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.TerminatedStringDataType
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadedIntegrationTest
import lol.fairplay.ghidraapple.actions.markasblock.ApplyNSConcreteGlobalBlock
import lol.fairplay.ghidraapple.actions.markasblock.ApplyNSConcreteStackBlock
import lol.fairplay.ghidraapple.core.createFunction
import lol.fairplay.ghidraapple.core.setNullTerminatedString
import org.junit.jupiter.api.Test
import kotlin.test.Ignore
import kotlin.test.assertEquals

@Suppress("ktlint:standard:max-line-length")
class BlockTests : AbstractGhidraHeadedIntegrationTest() {
    @Test
    fun testGlobalBlockWithArgs() {
        val builder = ProgramBuilder("airportd", "AARCH64:LE:64:AppleSilicon")

        builder.createLabel("1001945c0", "__NSConcreteGlobalBlock")

        // Create global block
        builder.setBytes(
            "100156148",
            bytes(
                0xc0,
                0x45,
                0x19,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x50,
                0x00,
                0x00,
                0x00,
                0x00,
                0xd0,
                0xea,
                0x02,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x28,
                0x61,
                0x15,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
            ),
        )

        // Create descriptor
        builder.setBytes(
            "100156128",
            bytes(
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x20,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0xaa,
                0xd4,
                0x12,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ),
        )

        // Add signature string "v32@?0@\"NSError\"8@\"NSArray\"16@\"NSURL\"24" as bytes

        builder.setNullTerminatedString("10012d4aa", """v32@?0@"NSError"8@"NSArray"16@"NSURL"24""", applyStringType = true)

        // TODO: Currently we rely on this string already being created, this seems like an unnecessary assumption
        builder.applyStringDataType("10012d4aa", TerminatedStringDataType.dataType, 1)

        val invokeFunction =
            builder.createFunction(
                "10002ead0",
                bytes(
                    0x7f,
                    0x23,
                    0x03,
                    0xd5,
                    0xff,
                    0x43,
                    0x01,
                    0xd1,
                    0xf6,
                    0x57,
                    0x02,
                    0xa9,
                    0xf4,
                    0x4f,
                    0x03,
                    0xa9,
                    0xfd,
                    0x7b,
                    0x04,
                    0xa9,
                    0xfd,
                    0x03,
                    0x01,
                    0x91,
                    0xf3,
                    0x03,
                    0x03,
                    0xaa,
                    0xe0,
                    0x03,
                    0x01,
                    0xaa,
                    0x28,
                    0x09,
                    0x00,
                    0xf0,
                    0x08,
                    0xc1,
                    0x42,
                    0xf9,
                    0x15,
                    0x01,
                    0x40,
                    0xf9,
                    0x28,
                    0x09,
                    0x00,
                    0xf0,
                    0x08,
                    0xbd,
                    0x42,
                    0xf9,
                    0x16,
                    0x01,
                    0x40,
                    0xb9,
                    0x76,
                    0x1b,
                    0x03,
                    0x94,
                    0xf4,
                    0x03,
                    0x00,
                    0xaa,
                    0xe0,
                    0x03,
                    0x13,
                    0xaa,
                    0xa3,
                    0x2d,
                    0x03,
                    0x94,
                    0xf4,
                    0x03,
                    0x01,
                    0xa9,
                    0xf5,
                    0x5b,
                    0x00,
                    0xa9,
                    0xe1,
                    0x07,
                    0x00,
                    0xf0,
                    0x21,
                    0x48,
                    0x13,
                    0x91,
                    0x80,
                    0x00,
                    0x80,
                    0x52,
                    0x49,
                    0x03,
                    0x03,
                    0x94,
                    0xfd,
                    0x7b,
                    0x44,
                    0xa9,
                    0xf4,
                    0x4f,
                    0x43,
                    0xa9,
                    0xf6,
                    0x57,
                    0x42,
                    0xa9,
                    0xff,
                    0x43,
                    0x01,
                    0x91,
                    0xff,
                    0x0f,
                    0x5f,
                    0xd6,
                ),
            )
//        val env = TestEnv()
//        env.launchDefaultTool(builder.program)
        builder.withTransaction {
            ApplyNSConcreteGlobalBlock(builder.addr("100156148")).applyTo(builder.program)
        }

        builder.program.listing
            .getDataAt(builder.addr("100156148"))
            .dataType
            .toString()

        // The invoke function should have the global block as the first argument, and appropriate second and third arguments
        assertEquals("NSError *64", invokeFunction.parameters[1].dataType.toString())
        assertEquals("NSArray *64", invokeFunction.parameters[2].dataType.toString())
        assertEquals("NSURL *64", invokeFunction.parameters[3].dataType.toString())
    }

    @Test
    fun testStackBlockWithCapturedVariables() {
        val builder = ProgramBuilder("airportd", "AARCH64:LE:64:AppleSilicon")

        // Create external symbol for stack block
        builder.createLabel("1001945c8", "__NSConcreteStackBlock")
        // Create GOT entry for stack block
        builder.createLabel("100155528", "PTR___NSConcreteStackBlock_100155528")
        builder.setBytes("100155528", bytes(0xc8, 0x45, 0x19, 0x00, 0x01, 0x00, 0x00, 0x00))

        // Set up block descriptor
        builder.setBytes(
            "1001563d8",
            bytes(
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x30,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x34,
                0x40,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x44,
                0x40,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x5a,
                0x58,
                0x12,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ),
        )

        // Set up flag value
        builder.setBytes("100121bb0", bytes(0x00, 0x00, 0x00, 0xc2, 0x00, 0x00, 0x00, 0x00))

        // Set up signature
        builder.setNullTerminatedString("10012585a", "v8@?0", applyStringType = true)

        val invokedFunction =
            builder.createFunction(
                "100006874",
                bytes(0x09, 0x20, 0x42, 0xa9, 0x28, 0x69, 0x00, 0xf9, 0xc0, 0x03, 0x5f, 0xd6),
            )

        // TODO: Add the two arguments
        val callerFunction =
            builder.createFunction(
                "1000067d4",
                bytes(
                    0x7f,
                    0x23,
                    0x03,
                    0xd5,
                    0xff,
                    0x43,
                    0x01,
                    0xd1,
                    0xfd,
                    0x7b,
                    0x04,
                    0xa9,
                    0xfd,
                    0x03,
                    0x01,
                    0x91,
                    0x68,
                    0x0a,
                    0x00,
                    0xf0,
                    0x08,
                    0xa1,
                    0x42,
                    0xf9,
                    0x08,
                    0x01,
                    0x40,
                    0xf9,
                    0xa8,
                    0x83,
                    0x1f,
                    0xf8,
                    0x08,
                    0x24,
                    0x40,
                    0xf9,
                    0xe9,
                    0x23,
                    0x00,
                    0x91,
                    0x70,
                    0x0a,
                    0x00,
                    0xf0,
                    0x10,
                    0x96,
                    0x42,
                    0xf9,
                    0xf1,
                    0x03,
                    0x09,
                    0xaa,
                    0x31,
                    0x5c,
                    0xed,
                    0xf2,
                    0x30,
                    0x0a,
                    0xc1,
                    0xda,
                    0xf0,
                    0x07,
                    0x00,
                    0xf9,
                    0xca,
                    0x08,
                    0x00,
                    0xf0,
                    0x40,
                    0xd9,
                    0x45,
                    0xfd,
                    0xe0,
                    0x0b,
                    0x00,
                    0xfd,
                    0x29,
                    0x41,
                    0x00,
                    0x91,
                    0x8a,
                    0x0a,
                    0x00,
                    0x90,
                    0x4a,
                    0x61,
                    0x0f,
                    0x91,
                    0x10,
                    0x00,
                    0x00,
                    0x90,
                    0x10,
                    0xd2,
                    0x21,
                    0x91,
                    0x30,
                    0x01,
                    0xc1,
                    0xda,
                    0xf0,
                    0xab,
                    0x01,
                    0xa9,
                    0xe0,
                    0x8b,
                    0x02,
                    0xa9,
                    0xe1,
                    0x23,
                    0x00,
                    0x91,
                    0xe0,
                    0x03,
                    0x08,
                    0xaa,
                    0x22,
                    0xa6,
                    0x03,
                    0x94,
                    0xa8,
                    0x83,
                    0x5f,
                    0xf8,
                    0x69,
                    0x0a,
                    0x00,
                    0xf0,
                    0x29,
                    0xa1,
                    0x42,
                    0xf9,
                    0x29,
                    0x01,
                    0x40,
                    0xf9,
                    0x3f,
                    0x01,
                    0x08,
                    0xeb,
                    0x81,
                    0x00,
                    0x00,
                    0x54,
                    0xfd,
                    0x7b,
                    0x44,
                    0xa9,
                    0xff,
                    0x43,
                    0x01,
                    0x91,
                    0xff,
                    0x0f,
                    0x5f,
                    0xd6,
                    0x98,
                    0xa5,
                    0x03,
                    0x94,
                ),
            )

//        val env = TestEnv()
//        env.launchDefaultTool(builder.program)

        // The command currently relies on this stack reference already existing
        // This seems like a potentially unnecessary assumption,
        // and we could consider finding this part of the responsibility of the command
        builder.createStackReference("100006810", RefType.WRITE, -0x48, SourceType.ANALYSIS, 1)
        // FINISHED SET UP

        // RUN COMMAND
        builder.withTransaction {
            ApplyNSConcreteStackBlock(callerFunction, builder.addr("100006810")).applyTo(builder.program)
        }

        // ASSERT OUTCOMES
        assertEquals("invoke_100006874", invokedFunction.name)

        val pointer = invokedFunction.parameters[0].dataType as Pointer
        val blockType = pointer.dataType as Structure
        assertEquals("Block_layout_100006810", blockType.name)
        assertEquals(0x30, blockType.length)
    }

    @Ignore("Not finished yet")
    @Test
    fun testStackBlockWithExplicitArguments() {
        val builder = ProgramBuilder("airportd", "AARCH64:LE:64:AppleSilicon")
        val invokedFunction = builder.createFunction("1000eafdc", TODO())

        val callerFunction = builder.createFunction("1000eaf1c", TODO())

        // TODO: All the set up again

        // Check that the arguments are added to the invoked function
        assertEquals("CWANQPElement *64", invokedFunction.parameters[1].dataType.toString())
        assertEquals("bool *64", invokedFunction.parameters[2].dataType.toString())
    }
}
