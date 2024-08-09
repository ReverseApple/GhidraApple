package lol.fairplay.ghidraapple.analysis.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor


class OCStructureAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER) {

    companion object {
        private const val NAME = "Objective-C Structures"
        private const val DESCRIPTION = ""
        private val PRIORITY = AnalysisPriority.BLOCK_ANALYSIS.after()
    }

    init {
        priority = PRIORITY
        setPrototype()
    }

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        val category = CategoryPath("/GA_OBJC")

        program.symbolTable.symbolIterator.filter { it.name.startsWith("_OBJC_CLASS_\$_") }.forEach {
            val className = it.name.removePrefix("_OBJC_CLASS_\$_")

            // Create a struct for the class following the naming scheme: `struct_<CLASSNAME>`
            val classStruct = StructureDataType(category, "struct_$className", 0)
            program.dataTypeManager.addDataType(classStruct, null)

            // add a typedef for the class struct as a pointer.
            val typedef = TypedefDataType(category, className, PointerDataType(classStruct), program.dataTypeManager)
            program.dataTypeManager.addDataType(typedef, null)
        }

        return true
    }

}
