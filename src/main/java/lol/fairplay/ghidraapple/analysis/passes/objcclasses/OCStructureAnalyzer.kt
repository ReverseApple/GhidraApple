package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.derefUntyped
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.get
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.deref
import lol.fairplay.ghidraapple.analysis.utilities.parseObjCListSection
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass


class OCStructureAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {

    companion object {
        private const val NAME = "Objective-C: Structures"
        private const val DESCRIPTION = ""
        val PRIORITY = AnalysisPriority.BLOCK_ANALYSIS.after()
    }

    lateinit var program: Program

    val structureCategory = CategoryPath("/GA_OBJC")

    init {
        priority = PRIORITY
        setPrototype()
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program

        return program.memory.getBlock("__objc_classlist") != null
                || program.memory.getBlock("__objc_protolist") != null
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog?): Boolean {
        monitor.message = "Reading list sections..."

        val classStructures = (parseObjCListSection(program, "__objc_classlist")?.associate { klassT ->
            // class_t[4]->class_rw[3]->name
            klassT[4].derefUntyped()[3].deref<String>() to klassT
        } ?: emptyMap()).toMutableMap()


        val protocolStructures = (parseObjCListSection(program, "__objc_protolist")?.associate { protoT ->
            // protocol_t[1]->name
            protoT[1].deref<String>() to protoT
        } ?: emptyMap()).toMutableMap()


        // Some class symbols that are not inside the objc::class_t namespace are prefixed with `_OBJC_CLASS_$_`
        // These are not parsable, but are still useful for analysis purposes.
        val externalClasses = program.symbolTable.symbolIterator.filter {
            it.name.startsWith("_OBJC_CLASS_\$_")
        }.mapNotNull {
            val className = it.name.removePrefix("_OBJC_CLASS_\$_")
            // just for sanity, ensure it's not already in either of the structure mappings.
            if (className !in classStructures && className !in protocolStructures) {
                className
            } else {
                null
            }
        }

        buildStructureTypes(classStructures, protocolStructures, externalClasses, monitor)

        // Recover the structure fields by parsing each eligible class into the analysis model.

        return true
    }

    private fun buildStructureTypes(
        klassData: Map<String, Data>,
        protoData: Map<String, Data>,
        externalClasses: List<String>,
        taskMonitor: TaskMonitor?
    ): Boolean {

        val parser = StructureParsing(program)
        val typeResolver = TypeResolver(program)

        taskMonitor?.maximum = (klassData.size + protoData.size + externalClasses.size).toLong()
        taskMonitor?.progress = 0
        taskMonitor?.message = "Creating class types..."

        protoData.forEach { (name, data) ->
            taskMonitor?.incrementProgress()
            val dataType = program.dataTypeManager.addDataType(StructureDataType(structureCategory, name, 0), null)
        }

        // Create class types with fields.
        klassData.forEach { (name, data) ->
            val dataType = program.dataTypeManager.addDataType(StructureDataType(structureCategory, name, 0), null)

            taskMonitor?.incrementProgress()

            // Attempt to parse the class into the analysis models.
            val model = runCatching {
                parser.parseClass(data.address.unsignedOffset)
            }.onFailure {
                Msg.error(this, "Could not parse class $name into a model: $it")
            }.getOrNull() ?: return@forEach

            // Create the instance variables for the structure.
            for (ivar in model.instanceVariables ?: return@forEach) {

                var fieldType = runCatching {
                    typeResolver.buildParsed(ivar.type)
                }.onFailure {
                    Msg.error(this, "Could not reconstruct type for ivar ${model.name}->${ivar.name}")
                }.getOrNull() ?: continue

                (dataType as Structure).insertAtOffset(
                    ivar.offset.toInt(),
                    fieldType,
                    ivar.size,
                    ivar.name,
                    null
                )
            }
        }

//        protoData.forEach { (name, data) ->
//            val dataType = program.dataTypeManager.addDataType(StructureDataType(structureCategory, name, 0), null)
//
//            taskMonitor?.incrementProgress()
//
//            val model = runCatching {
//                parser.parseProtocol(data.address.unsignedOffset)
//            }.onFailure {
//                Msg.error(this, "Could not parse protocol $name into a model: $it")
//            }.getOrNull() ?: return@forEach
//
//
//        }

        return true
    }
}


