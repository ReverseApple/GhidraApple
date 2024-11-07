package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidra.program.model.listing.Function
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.deref
import lol.fairplay.ghidraapple.analysis.utilities.dataBlocksForNamespace
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.get
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.longValue
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.tryResolveNamespace
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignatureType
import lol.fairplay.ghidraapple.core.objc.encodings.TypeNode
import lol.fairplay.ghidraapple.core.objc.encodings.parseSignature


private data class ProtocolT(
    val className: String,
    val methods: List<Pair<Function, EncodedSignature>>
)


class OCMethodAnalyzer : AbstractAnalyzer(
    NAME,
    DESCRIPTION,
    AnalyzerType.DATA_ANALYZER
) {
    lateinit var program: Program

    companion object {
        private const val NAME = "Objective-C Methods"
        private const val DESCRIPTION = "Analyze method signatures and apply types."
    }

    init {
        priority = OCClassFieldAnalyzer.PRIORITY.after()
        setSupportsOneTimeAnalysis()
        setPrototype()
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program
        return super.canAnalyze(program)
    }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog
    ): Boolean {
        // Analyze all method list structures in an Objective-C binary.

        val protocols = getProtocols(set) ?: return false
        val typeResolver = TypeResolver(program)

        program.withTransaction<Exception>("Retyping class methods...") {
            for (protocol in protocols) {
                val gaClassDT = typeResolver.tryResolveDefinedStruct(protocol.className) ?: continue

                for ((method, encSignature) in protocol.methods) {
                    TODO("Not yet implemented")
                }
            }
        }

        TODO("Not yet implemented")
    }

    private fun getProtocols(addresses: AddressSetView): List<ProtocolT>? {
        val protocolNs = tryResolveNamespace(program, "objc", "protocol_t") ?: return null
        var dataBlocks = dataBlocksForNamespace(program, protocolNs, addresses)
        var result = mutableListOf<ProtocolT>()

        for (protoStruct in dataBlocks) {
            val className = protoStruct[0].deref<String>()
            val methods = extractMethodSignatures(protoStruct) ?: continue

            result.add(ProtocolT(className, methods))
        }

        return result
    }

    private fun extractMethodSignatures(protoStruct: Data): List<Pair<Function, EncodedSignature>>? {
        val result = mutableListOf<Pair<Function, EncodedSignature>>()

        val extendedMethodTypesPtr = protoStruct[9]
        if (extendedMethodTypesPtr.longValue(false) == 0L) return null

        val extSigAddress = extendedMethodTypesPtr.longValue(false)

        // Ensure the method list field is present
        if (protoStruct[3].longValue(false) == 0L) return null

        // iterate through and bind method functions to their corresponding extended type signature
        val methodListStruct = protoStruct[3].deref<Data>()
        val entryCount = methodListStruct[1].longValue(false)

        for (i in 0 until entryCount) {
            val methodT = methodListStruct[2 + i.toInt()]
            val extendedSignature =
                program.listing.getDataAt(program.address(extSigAddress + i.toLong() * 8)).value as String

            // if the `method_t->imp` field is a nullptr, skip entry
            if (methodT[2].longValue(false) == 0L) continue

            // FIXME: fnAddress always appears to have nullptr as its value.
            val fnAddress = program.address(methodT[2].longValue(false))

            val functionEntity = program.functionManager.getFunctionAt(fnAddress) ?: continue

            result.add(functionEntity to parseSignature(extendedSignature, EncodedSignatureType.METHOD_SIGNATURE))
        }

        return result.toList()
    }

}
