package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.Undefined
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Library
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.GhidraTypeBuilder.Companion.OBJC_CLASS_CATEGORY
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.deref
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.derefUntyped
import lol.fairplay.ghidraapple.analysis.utilities.StructureHelpers.get
import lol.fairplay.ghidraapple.analysis.utilities.parseObjCListSection

class OCStructureAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {
    companion object {
        public const val NAME = "Objective-C: Structures"
        private const val DESCRIPTION = ""
        val PRIORITY = AnalysisPriority.BLOCK_ANALYSIS.after()
    }

    lateinit var program: Program

    init {
        priority = PRIORITY
        setDefaultEnablement(true)
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program

        return program.memory.getBlock("__objc_classlist") != null ||
            program.memory.getBlock("__objc_protolist") != null
    }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog?,
    ): Boolean {
        monitor.message = "Reading list sections..."

        val classStructures =
            (
                parseObjCListSection(program, "__objc_classlist")?.mapNotNull { klassT ->
                    // class_t[4]->class_rw[3]->name
                    runCatching {
                        klassT[4].derefUntyped()[3].deref<String>() to klassT
                    }.onFailure {
                        Msg.error(this, "Failed to parse class data at ${klassT.address}", it)
                    }.getOrNull()
                }?.toMap() ?: emptyMap()
            ).toMutableMap()

        val protocolStructures =
            (
                parseObjCListSection(program, "__objc_protolist")?.associate { protoT ->
                    // protocol_t[1]->name
                    protoT[1].deref<String>() to protoT
                } ?: emptyMap()
            ).toMutableMap()

        // Some class symbols that are not inside the objc::class_t namespace are prefixed with `_OBJC_CLASS_$_`
        // These are not parsable, but are still useful for analysis purposes.
        val externalClasses =
            program.symbolTable.symbolIterator.filter {
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

        return true
    }

    private fun buildStructureTypes(
        klassData: Map<String, Data>,
        protoData: Map<String, Data>,
        externalClasses: List<String>,
        taskMonitor: TaskMonitor?,
    ): Boolean {
        val parser = StructureParsing(program)
        val typeResolver = TypeResolver(program)

        taskMonitor?.maximum = (klassData.size + protoData.size + externalClasses.size).toLong()
        taskMonitor?.progress = 0

        taskMonitor?.message = "Creating nullary types..."

        taskMonitor?.message = "Creating structs and namespaces for external classes..."
        externalClasses.forEach(::handleExternalClass)

        taskMonitor?.message = "Creating structs for protocols..."
        protoData.keys.forEach { name ->
            taskMonitor?.incrementProgress()

            program.dataTypeManager.addDataType(StructureDataType(OBJC_CLASS_CATEGORY, "<$name>", 0), null)
        }
        taskMonitor?.message = "Creating structs for internal classes..."
        // Create class types with fields.
        klassData.forEach { (name, data) ->
            val dataType = program.dataTypeManager.addDataType(StructureDataType(OBJC_CLASS_CATEGORY, name, 0), null)

            taskMonitor?.incrementProgress()

            // Attempt to parse the class into the analysis models.
            val model =
                runCatching {
                    parser.parseClass(data.address.unsignedOffset)
                }.onFailure {
                    Msg.error(this, "Could not parse class $name into a model: $it")
                }.getOrNull() ?: return@forEach

            // Create the instance variables for the structure.
            for (ivar in model.instanceVariables ?: return@forEach) {
                val fieldType =
                    runCatching {
                        // Some ivars can have no type string, and only a size
                        ivar.type?.let { typeResolver.buildParsed(it) } ?: Undefined.getUndefinedDataType(ivar.size)
                    }.onFailure {
                        Msg.error(this, "Could not reconstruct type for ivar ${model.name}->${ivar.name}")
                    }.getOrNull() ?: continue

                (dataType as Structure).insertAtOffset(
                    ivar.offset.toInt(),
                    fieldType,
                    ivar.size,
                    ivar.name,
                    null,
                )
            }
        }
        // Set the `__objc_ivar` section back to read-only, so that the offsets there are used by the decompiler
        program.memory.getBlock("__objc_ivar")?.isWrite = false
        return true
    }

    /**
     * - Creates an empty structure datatype for the class, so we can use this to type variables and parameters
     * - Create a [GhidraClass] that is part of the correct [Library] namespace, so we can associate method thunks with it
     * The [GhidraClass] namespace is left empty, because inferring the existence of methods is handled by other analyses
     *
     */
    private fun handleExternalClass(className: String) {
        // Check if there already is a namespace with this name
        if (program.symbolTable.classNamespaces.asSequence().any { it.name == className }) {
            Msg.debug(this, "Class $className already exists")
            return
        }

        Msg.debug(this, "Creating nullary: $className")
        // Create empty struct
        program.dataTypeManager.addDataType(StructureDataType(OBJC_CLASS_CATEGORY, className, 0), null)
        // Find the existing [Library] namespace that has the symbol _OBJC_CLASS_$_${it}
        val externalClassSymbol =
            with(program.externalManager) {
                externalLibraryNames
                    // For each collection of external locations
                    .map { getExternalLocations(it).asSequence().toList() }
                    // Find the one that has a symbol like `_OBJC_CLASS_$_${cls.name}`
                    .mapNotNull { locations ->
                        locations.singleOrNull { it.label == "_OBJC_CLASS_\$_$className" }
                    }.singleOrNull()
            }
        if (externalClassSymbol != null) {
            val externalLibrary: Library = externalClassSymbol.parentNameSpace as Library
            // Create the new class namespace
            val classNameSpace: GhidraClass = program.symbolTable.createClass(externalLibrary, className, SourceType.ANALYSIS)
            // Move the symbol to the new namespace
            externalClassSymbol.symbol.setNamespace(classNameSpace)
        } else {
            Msg.error(this, "Could not find external class symbol for $className")
        }
    }
}
