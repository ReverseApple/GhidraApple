package lol.fairplay.ghidraapple.actions

import ghidra.framework.cmd.Command
import ghidra.program.model.listing.Program
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCMethodAnalyzer.Companion.PROPERTY_TAG_GETTER
import lol.fairplay.ghidraapple.analysis.passes.objcclasses.OCMethodAnalyzer.Companion.PROPERTY_TAG_SETTER
import lol.fairplay.ghidraapple.analysis.utilities.hasTag

class InlinePropertyAccessorsCmd(
    val inline: Boolean = true,
) : Command<Program> {
    override fun applyTo(program: Program): Boolean {
        program.withTransaction<Exception>("Inline Property Accessors") {
            program.functionManager.getFunctions(true)
                .filter { it.hasTag(PROPERTY_TAG_SETTER) || it.hasTag(PROPERTY_TAG_GETTER) }
                .filter {
                    // Filter to only include functions that have 2 instructions (with 4 bytes each)
                    it.body.numAddresses == 8L
                }
                .forEach {
                    it.isInline = inline
                }
        }
        return true
    }

    override fun getStatusMsg(): String? {
        return null
    }

    override fun getName(): String {
        return "Inline Property Accessors"
    }
}
