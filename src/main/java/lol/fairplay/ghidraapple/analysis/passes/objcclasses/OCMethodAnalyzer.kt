package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.parseObjCListSection
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass

class OCMethodAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {

    lateinit var program: Program
    lateinit var log: MessageLog

    companion object {
        const val NAME = "Objective-C: Method Analyzer"
        const val DESCRIPTION = ""
        val PRIORITY = OCStructureAnalyzer.PRIORITY.after()
    }

    init {
        priority = PRIORITY
        setPrototype()
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program
        return program.memory.getBlock("__objc_classlist") != null
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        this.log = log

        monitor.message = "Reading classes..."

        val klasses = parseObjCListSection(program, "__objc_classlist") ?: return false

        monitor.maximum = klasses.size.toLong()
        monitor.message = "Parsing class structures..."

        val parser = StructureParsing(program)
        klasses.forEach { klassData ->
            monitor.incrementProgress()

            val model = runCatching {
                parser.parseClass(klassData.address.unsignedOffset)
            }.onFailure { exception ->
                Msg.error(this, "Could not parse class at ${klassData.address.unsignedOffset}", exception)
            }.getOrNull() ?: return@forEach

            propagateSignatures(model, monitor)
        }

        return true
    }

    private fun propagateSignatures(klass: OCClass, taskMonitor: TaskMonitor?) {
        taskMonitor?.message = "Propagating signatures: ${klass.name}"

        val typeResolver = TypeResolver(program)
        val methods = klass.resolvedMethods()

        methods?.forEach { resolution ->
            val method = resolution.method()

            if (method.implAddress == null) {
                Msg.error(this, "Method ${klass.name}->${method.name} has no implementation address!")
                return@forEach
            }

            val fcnEntity = program.listing.getFunctionAt(program.address(method.implAddress))
            if (fcnEntity == null) {
                Msg.error(this, "Could not find method ${klass.name}->${method.name} at ${method.implAddress}")
                return@forEach
            }

            val encSignature = resolution.bestSignature().first ?: return@forEach

            // Reconstruct the return type for the method.
            val returnDT = runCatching {
                typeResolver.buildParsed(encSignature.returnType.first)
            }.onFailure { exception ->
                Msg.error(this, "Could not parse return type for ${klass.name}->${method.name}", exception)
            }.getOrNull()

            // starting at 2 to skip `self` and SEL.
            val parameters = mutableListOf<ParameterImpl>()

            val recvType = typeResolver.tryResolveDefinedStructPtr(klass.name)
                ?: program.dataTypeManager.getDataType("/_objc2_/ID")!!

            parameters.add(ParameterImpl("self", recvType, 0, program))
            parameters.add(ParameterImpl("selector", program.dataTypeManager.getDataType("/_objc2_/SEL")!!, 8, program))
            var newNames = parameterNamesForMethod(method.name)

            // Reconstruct and apply parameter types.
            encSignature.parameters.forEachIndexed { i, (type, stackOffset, modifiers) ->
                val paramDT = runCatching {
                    typeResolver.buildParsed(type)
                }.onFailure { exception ->
                    Msg.error(
                        this,
                        "Could not parse argument ${i + 2} type for ${klass.name}->${method.name}",
                        exception
                    )
                }.getOrNull() ?: return@forEachIndexed

                Msg.info(this, "Applying argument ${i + 2} type to function for ${klass.name}->${method.name}...")

                parameters.add(ParameterImpl(newNames[i], paramDT, stackOffset, program))
            }

            val returnVar = fcnEntity.getReturn()
            if (returnDT != null) {
                returnVar.setDataType(returnDT, SourceType.ANALYSIS)
            }

            println(newNames)

            fcnEntity.updateFunction(
                null,
                returnVar,
                parameters,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true,
                SourceType.ANALYSIS
            )

        }
    }

    fun splitCamelCase(input: String): List<String> {
        return input.split(Regex("(?<=[a-zA-Z])(?=[A-Z])"))
    }

    private fun parameterNamesForMethod(methodName: String): List<String> {
        // todo: make this optional.
        // create parameter names, acknowledging common objective-c naming conventions.

        val keywords = listOf("with", "for", "from", "to", "in", "at")

        val baseNames = methodName.split(":")
            .filter{ !it.isEmpty() }
            .map { part ->
            val ccSplit = splitCamelCase(part)

            val matchIndex = ccSplit.indexOfFirst {
                it.lowercase() in keywords
            }
            val match = ccSplit.getOrNull(matchIndex) ?: return@map part

            when (match.lowercase()) {
                "for" -> {
                    if (part.startsWith(match)) {
                        part.substringAfter(match).replaceFirstChar { it.lowercase() }
                    } else {
                        part.substringAfter(match).replaceFirstChar { it.lowercase() }
                    }
                }
                in keywords -> part.substringAfter(match).replaceFirstChar { it.lowercase() }
                else -> part
            }
        }

        val uniqueNames = mutableMapOf<String, Int>(
            "self" to 0,
            "selector" to 0,
        )

        val result = baseNames.map { name ->
            val count = uniqueNames.getOrDefault(name, 0)
            uniqueNames[name] = count + 1
            if (count > 0) "${name}_$count" else name
        }

        return result.drop(2)
    }

}