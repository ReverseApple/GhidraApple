package lol.fairplay.ghidraapple.analysis.passes.strings

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.lang.OperandType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.scalar.Scalar
import ghidra.program.util.ContextEvaluatorAdapter
import ghidra.program.util.SymbolicPropogator
import ghidra.util.Msg
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor

/**
 * Reconstructs small string literals that Swift encodes directly in registers.
 *
 * A Swift string of at most 15 ASCII bytes is stored inline in the 16 bytes of `_StringObject`
 * rather than behind a pointer. The compiler therefore never emits the characters as data — they
 * only ever exist as a pair of 64-bit immediates, which is why they are invisible to Ghidra's
 * normal string search.
 *
 * ## Layout
 *
 * ```
 * byte:  0 .......................... 14                    15
 *       [ up to 15 content bytes, zero-padded ][ discriminator | count ]
 * ```
 *
 * Byte 15 packs the flags in its high nibble (bit 63 isImmortal, 62 isASCII, 61 isSmall,
 * 60 isForeign) and the character count in its low nibble. `"Hi"` is `0x48 0x69 0*13 0xE2`.
 *
 * ## Why this does not pattern-match instructions
 *
 * The two words are built completely differently per target, and neither shape is a fixed
 * instruction sequence:
 *
 * ```
 * ; arm64 — 16 bits of immediate at a time, then both words stored together
 * mov  x8, #0x4946
 * movk x8, #0x3065, lsl #16
 * movk x8, #0x556d, lsl #32
 * movk x8, #0x5848, lsl #48
 * stp  x8, x23, [x0, #0x20]     ; x23 holds the discriminator, set once and reused
 *
 * ; x86-64 — one immediate fills a word, and the two halves are stored separately
 * movabsq $0x5848556d30654946, %rax
 * movq    %rax, 0x20(%r15)
 * movq    %rbx, 0x28(%r15)      ; %rbx holds the discriminator, set once and reused
 * ```
 *
 * The discriminator register is hoisted out of loops and kept alive across calls, so the
 * instruction that defines it can be arbitrarily far away — or absent from the block entirely.
 * Instead of matching mnemonics, this analyzer asks [SymbolicPropogator] for the constant value
 * of each register at each instruction and reassembles the 16 bytes from the two words that end
 * up adjacent, either in memory or in a consecutive ABI register pair.
 *
 * ## References
 *
 * - [StringObject](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/StringObject.swift)
 * - [SmallString](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/SmallString.swift)
 */
class SmallStringLiteralAnalyzer : AbstractAnalyzer(
    NAME,
    DESCRIPTION,
    AnalyzerType.FUNCTION_ANALYZER,
) {
    companion object {
        private const val NAME = "Small String Literal Reconstruction"
        private const val DESCRIPTION =
            "Reconstructs Swift small string literals held inline in register pairs (arm64 and x86-64)"

        private const val WORD_SIZE = 8L
        private const val STRING_OBJECT_SIZE = 16
        private const val MAX_SMALL_STRING_LENGTH = 15

        /** isSmall (bit 61) set and isForeign (bit 60) clear, both within byte 15. */
        private const val DISCRIMINATOR_MASK = 0x30
        private const val DISCRIMINATOR_SMALL = 0x20

        private const val PRINTABLE_ASCII_MIN = 0x20
        private const val PRINTABLE_ASCII_MAX = 0x7e

        private val SUPPORTED_PROCESSORS = setOf("AARCH64", "x86")

        /**
         * Registers that can hold the two halves of a `String` passed to, or returned from, a
         * call. A `String` occupies two consecutive slots, but it is not aligned to a slot pair:
         * `print(_:separator:terminator:)` puts its separator in `x1`/`x2`, so every adjacent
         * pair has to be considered, not just the even-aligned ones.
         */
        private val ARM64_ABI_REGISTERS = listOf("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7")
        private val X86_ABI_REGISTERS = listOf("RDI", "RSI", "RDX", "RCX", "R8", "R9")
        private val X86_RETURN_REGISTERS = "RAX" to "RDX"

        /**
         * Rebuilds the string from the two words of a `_StringObject`, or returns null if they do
         * not describe a small ASCII string.
         *
         * Every field is checked — the discriminator bits, the count, the zero padding after the
         * content and the content bytes themselves. That strictness is what makes the analyzer
         * usable: candidate word pairs are cheap to produce and mostly junk, so the decoder, not
         * the search, is what has to reject them.
         */
        internal fun decodeSmallString(
            lowWord: Long,
            highWord: Long,
        ): String? = decodeSmallString(wordsToBytes(lowWord, highWord))

        internal fun decodeSmallString(bytes: ByteArray): String? {
            if (bytes.size < STRING_OBJECT_SIZE) return null

            val discriminator = bytes[15].toInt() and 0xff
            if (discriminator and DISCRIMINATOR_MASK != DISCRIMINATOR_SMALL) return null

            val count = discriminator and 0x0f
            if (count == 0) return null
            if ((count until MAX_SMALL_STRING_LENGTH).any { bytes[it] != 0.toByte() }) return null

            val characters = CharArray(count)
            for (index in 0 until count) {
                val byte = bytes[index].toInt() and 0xff
                val printable = byte in PRINTABLE_ASCII_MIN..PRINTABLE_ASCII_MAX || byte in 0x09..0x0d
                if (!printable) return null
                characters[index] = byte.toChar()
            }
            return String(characters)
        }

        private fun wordsToBytes(
            lowWord: Long,
            highWord: Long,
        ): ByteArray =
            ByteArray(STRING_OBJECT_SIZE) { index ->
                val word = if (index < WORD_SIZE) lowWord else highWord
                ((word shr ((index % WORD_SIZE.toInt()) * 8)) and 0xff).toByte()
            }
    }

    init {
        setDefaultEnablement(true)
        setPrototype()
    }

    // The inline 16-byte _StringObject only exists on 64-bit targets.
    override fun canAnalyze(program: Program): Boolean =
        program.defaultPointerSize == 8 &&
            program.language.processor.toString() in SUPPORTED_PROCESSORS

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        var resolved = 0
        try {
            for (function in program.functionManager.getFunctions(set, true)) {
                monitor.checkCancelled()
                resolved += analyzeFunction(program, function, monitor)
                monitor.message = "Small strings resolved: $resolved"
            }
        } catch (_: CancelledException) {
            return false
        }
        return true
    }

    private fun analyzeFunction(
        program: Program,
        function: Function,
        monitor: TaskMonitor,
    ): Int {
        // recordStartEndState must be on: without it getRegisterValue ignores the address it is
        // given and answers with whatever the propagation happened to end on.
        val propagator = SymbolicPropogator(program, true)
        // saveContext = true, so the per-instruction register values stay queryable afterwards.
        propagator.flowConstants(
            function.entryPoint,
            function.body,
            ContextEvaluatorAdapter(),
            true,
            monitor,
        )

        val abiPairs = abiRegisterPairs(program)
        val storedWords = mutableMapOf<Slot, Long>()
        val freshRegisters = mutableSetOf<String>()
        var resolved = 0

        for (instruction in program.listing.getInstructions(function.body, true)) {
            monitor.checkCancelled()

            // A String written to memory: the content word lands 8 bytes below the discriminator.
            for ((slot, word) in wordsStoredBy(instruction, propagator)) {
                val contentWord = storedWords[slot.previous()]
                if (contentWord != null && comment(program, instruction.address, contentWord, word)) {
                    resolved++
                }
                storedWords[slot] = word
            }

            // A String handed to a call or returned: the two words sit in adjacent ABI registers.
            // Both halves must have been set since the previous call, or this is just whatever an
            // earlier String left behind — argument registers stay constant across unrelated calls,
            // and reporting those leftovers buries the real hits.
            if (instruction.flowType.isCall || instruction.flowType.isTerminal) {
                for ((contentRegister, discriminatorRegister) in abiPairs) {
                    if (contentRegister.name !in freshRegisters) continue
                    if (discriminatorRegister.name !in freshRegisters) continue
                    val contentWord = registerValue(propagator, instruction, contentRegister) ?: continue
                    val discriminator = registerValue(propagator, instruction, discriminatorRegister) ?: continue
                    if (comment(program, instruction.address, contentWord, discriminator)) resolved++
                }
            }

            if (instruction.flowType.isCall) {
                freshRegisters.clear()
            } else {
                // Track by base register: `mov w1, #0x20` is what makes x1 fresh.
                instruction.resultObjects
                    .filterIsInstance<Register>()
                    .forEach { freshRegisters.add(it.baseRegister.name) }
            }
        }
        return resolved
    }

    /**
     * The 64-bit words this instruction writes to memory, keyed by the slot they are written to.
     *
     * A slot is "base register plus displacement" rather than a resolved address, because the base
     * is typically a fresh heap pointer whose value is unknown. That is enough to tell whether two
     * writes are 8 bytes apart, which is all the pairing needs. `stp` writes two words in one
     * instruction, so the source operands are numbered off the displacement in order.
     */
    private fun wordsStoredBy(
        instruction: Instruction,
        propagator: SymbolicPropogator,
    ): List<Pair<Slot, Long>> {
        // Operand ref types do not mark the destination of a store (arm64 `stp` reports DATA for
        // its memory operand), so the pcode is what says whether this instruction writes memory.
        if (instruction.pcode.none { it.opcode == PcodeOp.STORE }) return emptyList()

        val destination =
            (0 until instruction.numOperands)
                .firstOrNull { OperandType.isDynamic(instruction.getOperandType(it)) }
                ?: return emptyList()

        val operandObjects = instruction.getOpObjects(destination)
        val base = operandObjects.filterIsInstance<Register>().firstOrNull() ?: return emptyList()
        val displacement = operandObjects.filterIsInstance<Scalar>().firstOrNull()?.value ?: 0L

        val sources = (0 until instruction.numOperands).filter { it != destination }
        return sources.mapIndexedNotNull { position, operand ->
            val word = operandValue(instruction, operand, propagator) ?: return@mapIndexedNotNull null
            Slot(base.name, displacement + position * WORD_SIZE) to word
        }
    }

    /** The constant value of an operand, whether it is an immediate or a register. */
    private fun operandValue(
        instruction: Instruction,
        operand: Int,
        propagator: SymbolicPropogator,
    ): Long? {
        instruction.getScalar(operand)?.let { return it.value }
        val register = instruction.getRegister(operand) ?: return null
        return registerValue(propagator, instruction, register)
    }

    private fun registerValue(
        propagator: SymbolicPropogator,
        instruction: Instruction,
        register: Register,
    ): Long? {
        if (register.bitLength > 64) return null
        val value = propagator.getRegisterValue(instruction.address, register) ?: return null
        // A value expressed relative to another register is not a constant we can decode.
        return if (value.isRegisterRelativeValue) null else value.value
    }

    private fun abiRegisterPairs(program: Program): List<Pair<Register, Register>> {
        val names =
            if (program.language.processor.toString() == "AARCH64") {
                ARM64_ABI_REGISTERS.zipWithNext()
            } else {
                X86_ABI_REGISTERS.zipWithNext() + X86_RETURN_REGISTERS
            }
        return names.mapNotNull { (low, high) ->
            val lowRegister = program.getRegister(low) ?: return@mapNotNull null
            val highRegister = program.getRegister(high) ?: return@mapNotNull null
            lowRegister to highRegister
        }
    }

    /** Annotates [address] with the decoded string. Returns false if there is nothing to say. */
    private fun comment(
        program: Program,
        address: Address,
        contentWord: Long,
        discriminatorWord: Long,
    ): Boolean {
        val value = decodeSmallString(contentWord, discriminatorWord) ?: return false
        val comment = "Small string: \"${value.escaped()}\""
        return runCatching {
            val codeUnit = program.listing.getCodeUnitAt(address) ?: return@runCatching false
            val existing = codeUnit.getComment(CommentType.EOL)
            if (existing != null && existing.contains(comment)) return@runCatching false
            codeUnit.setComment(
                CommentType.EOL,
                if (existing.isNullOrBlank()) comment else "$existing | $comment",
            )
            true
        }.onFailure {
            Msg.warn(this, "Could not comment small string at $address: ${it.message}")
        }.getOrDefault(false)
    }

    /** Keeps control characters from breaking the single-line comment they end up in. */
    private fun String.escaped(): String =
        buildString {
            for (character in this@escaped) {
                when (character) {
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    else -> append(character)
                }
            }
        }

    /** A memory location as "base register + displacement"; see [wordsStoredBy]. */
    private data class Slot(val base: String, val displacement: Long) {
        fun previous() = copy(displacement = displacement - WORD_SIZE)
    }
}
