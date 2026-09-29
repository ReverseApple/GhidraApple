package lol.fairplay.ghidraapple.analysis.passes.strings

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor

/**
 * Reconstructs cross-references for string literals calculated via adrp+add(+sub) sequences.
 *
 * Detects the following ARM64 patterns:
 *
 *   adrp  xN, page_base
 *   add   xN, xN, #offset
 *
 *   adrp  xN, page_base
 *   add   xN, xN, #offset
 *   sub   xM, xN, #adjustment
 *
 * For each sequence, computes the resulting address and checks whether a string
 * exists there. If so, adds a DATA reference from the `add` (or `sub`) instruction
 * to the string address, and adds an EOL comment showing the string value.
 *
 * This approach is intentionally simple and language-agnostic — it works for
 * Swift, Objective-C, and any other code that uses adrp+add to reference strings.
 */
class StringLiteralXRefAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER) {
    companion object {
        private const val NAME = "String Literal Cross-Reference Reconstruction"
        private const val DESCRIPTION =
            "Reconstructs xrefs for string literals calculated via adrp+add(+sub) sequences"

        private const val MAX_FORWARD_STEPS = 4
    }

    init {
        setDefaultEnablement(true)
        setPrototype()
    }

    override fun canAnalyze(program: Program): Boolean =
        program.language.processor ==
            ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("AARCH64")

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        val listing = program.listing
        val refMgr = program.referenceManager
        var count = 0

        try {
            val instructions = listing.getInstructions(set, true)

            while (instructions.hasNext()) {
                if (monitor.isCancelled) throw CancelledException()

                val inst = instructions.next() ?: continue

                // Anchor on adrp
                if (inst.mnemonicString != "adrp") continue

                val adrpDestReg = inst.getRegister(0) ?: continue
                val pageBase = getAdrpBase(inst) ?: continue

                // Look for add immediately after that reads and writes in the same register
                val addInst =
                    findNextInstruction(listing, inst, MAX_FORWARD_STEPS) {
                        it.mnemonicString == "add" &&
                            it.getRegister(0)?.name == adrpDestReg.name &&
                            it.getRegister(1)?.name == adrpDestReg.name
                    } ?: continue

                val addOffset = addInst.getScalar(2)?.unsignedValue ?: continue

                // Check for optional sub after the add
                val subInst =
                    findNextInstruction(listing, addInst, MAX_FORWARD_STEPS) {
                        it.mnemonicString == "sub" &&
                            it.getRegister(1)?.name == adrpDestReg.name &&
                            it.getScalar(2) != null // immediate only
                    }

                // The anchor instruction to annotate and the final address
                val (anchorInst, stringAddr) =
                    if (subInst != null) {
                        // sub is a Swift ABI artifact — discard its offset, use add address
                        subInst to tryAddress(pageBase, addOffset)
                    } else {
                        addInst to tryAddress(pageBase, addOffset)
                    }

                val stringAddr2 = stringAddr ?: continue

                // Only proceed if there is actually a string at that address
                val stringValue = readStringAt(program, stringAddr2) ?: continue

                runCatching {
                    if (refMgr.getReference(anchorInst.address, stringAddr2, 0) == null) {
                        refMgr.addMemoryReference(
                            anchorInst.address,
                            stringAddr2,
                            RefType.DATA,
                            SourceType.ANALYSIS,
                            0,
                        )
                    }
                }.onFailure {
                    Msg.warn(this, "Could not add xref at ${anchorInst.address}: ${it.message}")
                }

                runCatching {
                    val codeUnit = listing.getCodeUnitAt(anchorInst.address) ?: return@runCatching
                    val comment = "\"$stringValue\""
                    val existing = codeUnit.getComment(CommentType.EOL)
                    if (existing == null || !existing.contains(comment)) {
                        val mergedComment =
                            if (existing.isNullOrBlank()) {
                                comment
                            } else {
                                "$existing | $comment"
                            }
                        codeUnit.setComment(CommentType.EOL, mergedComment)
                    }
                }.onFailure {
                    Msg.warn(this, "Could not set comment at ${anchorInst.address}: ${it.message}")
                }

                count++
                monitor.message = "String xrefs resolved: $count"
            }
        } catch (_: CancelledException) {
            return false
        }

        monitor.message = "String xrefs resolved: $count"
        return true
    }

    /**
     * Scans forward from [from] up to [maxSteps] instructions, returning the first
     * instruction that satisfies [predicate], or null if none is found.
     * Stops early if a branch instruction is encountered.
     */
    private fun findNextInstruction(
        listing: Listing,
        from: Instruction,
        maxSteps: Int,
        predicate: (Instruction) -> Boolean,
    ): Instruction? {
        var current = from
        repeat(maxSteps) {
            current = listing.getInstructionAfter(current.address) ?: return null

            val mnemonic = current.mnemonicString
            if (mnemonic == "bl" || mnemonic == "blr" || mnemonic == "b" ||
                mnemonic == "br" || mnemonic.startsWith("b.") || mnemonic == "ret" ||
                mnemonic == "cbz" || mnemonic == "cbnz" || mnemonic == "tbz" || mnemonic == "tbnz"
            ) {
                return null
            }
            if (predicate(current)) return current
        }
        return null
    }

    /**
     * Extracts the resolved page base address from an ADRP instruction.
     * Prefers already-resolved memory references, falls back to scalar.
     */
    private fun getAdrpBase(adrpInst: Instruction): Address? {
        val refs = adrpInst.referencesFrom
        if (refs.isNotEmpty()) return refs.first().toAddress
        val scalar = adrpInst.getScalar(1) ?: return null
        return adrpInst.address.addressSpace.getAddress(scalar.unsignedValue)
    }

    /**
     * Safely computes pageBase + offset, returning null on overflow.
     */
    private fun tryAddress(
        pageBase: Address,
        offset: Long,
    ): Address? {
        return runCatching { pageBase.add(offset) }.getOrNull()
    }

    /**
     * Reads the string value at [addr] from the program listing.
     * Returns null if there is no string data there.
     */
    private fun readStringAt(
        program: Program,
        addr: Address,
    ): String? {
        return runCatching {
            val data = program.listing.getDataAt(addr) ?: return null
            val value = data.value
            if (value is String && value.isNotEmpty()) value else null
        }.getOrNull()
    }
}
