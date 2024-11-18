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
import lol.fairplay.ghidraapple.analysis.utilities.getMembers
import lol.fairplay.ghidraapple.analysis.utilities.tryResolveNamespace


class OCStructureAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {

    companion object {
        private const val NAME = "Objective-C Structures"
        private const val DESCRIPTION = ""
        private val PRIORITY = AnalysisPriority.BLOCK_ANALYSIS.after()
    }

    var classNamespace: Namespace? = null
    lateinit var program: Program

    init {
        priority = PRIORITY
        setPrototype()
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program
        return true
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog?): Boolean {
        classNamespace = tryResolveNamespace(program, "objc", "class_t") ?: return false
        val category = CategoryPath("/GA_OBJC")
        val namespace = classNamespace!!

        monitor.message = "Creating structures..."
        val definedStructures = mutableMapOf<String, DataType>()
        val idealStructures = mutableMapOf<String, Data>()
        namespace.getMembers().forEach { member ->
            if (member.name !in idealStructures) {
                val classStruct = StructureDataType(category, member.name, 0)
                definedStructures[member.name] = program.dataTypeManager.addDataType(classStruct, null)
                println("OCStructureAnalyzer: added ${member.name} structure.")

                idealStructures[member.name] = program.listing.getDefinedDataAt(member.address)
            } else {
                val data = idealStructures[member.name]!!
                val superclassExisting = data[0].derefUntyped()
                if (superclassExisting.primarySymbol.name.startsWith("_OBJC_METACLASS_\$")) {
                    idealStructures[member.name] = program.listing.getDefinedDataAt(member.address)
                }
            }
        }

        program.symbolTable.symbolIterator.filter {
            it.name.startsWith("_OBJC_CLASS_\$_")
        }.forEach {
            val className = it.name.removePrefix("_OBJC_CLASS_\$_")
            if (className !in definedStructures) {
                val classStruct = StructureDataType(category, className, 0)
                definedStructures[className] = program.dataTypeManager.addDataType(classStruct, null)
                println("OCStructureAnalyzer: added structure for external class $className")
            }
        }

        monitor.message = "Creating fields..."
        monitor.maximum = idealStructures.size.toLong()
        monitor.progress = 0

        val context = StructureParsing(program)
        val typeResolver = TypeResolver(program)

        program.withTransaction<Exception>("Applying class structure fields.") {
            for ((name, data) in idealStructures) {
                monitor.incrementProgress()

                val structAddress = data.address
                val classModel = context.parseClass(structAddress.unsignedOffset) ?: continue
                val definedStructure = definedStructures[name] ?: continue

                println("CLASS $name")
                for (ivar in classModel.instanceVariables ?: continue) {
                    var fieldType: DataType? = null
                    try {
                        println(ivar.name)
                        println(ivar.type)
                        fieldType = typeResolver.buildParsed(ivar.type) ?: continue
                    } catch (error: NotImplementedError) {
                        Msg.error(this, "Not supported for recovery: $error")
                        continue
                    }

                    (definedStructure as Structure).insertAtOffset(
                        ivar.offset.toInt(),
                        fieldType,
                        ivar.size,
                        ivar.name,
                        null
                    )
                    println("    -> ${ivar.name}: $fieldType (${ivar.type})")
                }
            }
        }

        return true
    }

}
