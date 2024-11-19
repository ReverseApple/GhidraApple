package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.idealClassStructures
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass

class OCClassPropertiesAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {

    companion object {
        const val NAME = "Objective-C: Class Properties"
        const val DESCRIPTION = "Apply property types to their corresponding methods. Depends on structure analysis pass."
        val PRIORITY = OCStructureAnalyzer.PRIORITY.after()
    }

    init {
        priority = PRIORITY
        setPrototype()
        setSupportsOneTimeAnalysis()
    }

    lateinit var program: Program

    override fun canAnalyze(program: Program): Boolean {
        this.program = program
        return program.memory.getBlock("__objc_classlist") != null
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {

        monitor.message = "Analyzing class structures..."
        monitor.isIndeterminate = true
        monitor.progress = 0

        val structures = idealClassStructures(program) ?: return false

        monitor.maximum = structures.size.toLong()
        monitor.isIndeterminate = false

        val context = StructureParsing(program)
        val typeResolver = TypeResolver(program)

        val models = structures.map { (name, data) ->
            monitor.incrementProgress()
            var parsed: OCClass? = null

            try {
                parsed = context.parseClass(data.address.unsignedOffset)
            } catch (e: Exception) {
                Msg.error(this, "Could not parse class $name into a model: $e")
                return@map null
            } catch (e: Error) {
                Msg.error(this, "Could not parse class $name into a model: $e")
                return@map null
            }

            return@map parsed
        }.filterNotNull()

        monitor.message = "Analyzing class models..."
        monitor.progress = 0
        monitor.maximum = models.size.toLong()

        program.withTransaction<Exception>("Apply types") {
            for (klass in models) {
                monitor.incrementProgress()

                monitor.message = "Analyzing properties: ${klass.name}"
                Msg.info(this, "Analyzing properties for ${klass.name}")
                val properties = klass.getCollapsedProperties() ?: continue
                val methodMapping = klass.baseMethods?.associateBy { it.name } ?: continue

                properties.forEach { property ->
                    val methodGetter = methodMapping[property.name] ?: return@forEach

                    val setterName = "set${property.name[0].uppercase()}${property.name.substring(1)}:"
                    val methodSetter = methodMapping[setterName] ?: return@forEach

                    val propertyDataType = runCatching {
                        val parsed = property.type?.first ?: return@runCatching null
                        typeResolver.buildParsed(parsed)
                    }.onFailure {
                        Msg.error(this, "Failed to recover type for ${property.name} ${property.type}")
                    }.getOrNull() ?: return@forEach

                    val fnGetter = program.functionManager.getFunctionAt(program.address(methodGetter.implAddress!!.toLong()))
                    val fnSetter = program.functionManager.getFunctionAt(program.address(methodSetter.implAddress!!.toLong()))

                    fnGetter.setReturnType(propertyDataType, SourceType.ANALYSIS)
                    fnSetter.getParameter(2).setDataType(propertyDataType, SourceType.ANALYSIS)
                }
            }
        }

        return true
    }

}
