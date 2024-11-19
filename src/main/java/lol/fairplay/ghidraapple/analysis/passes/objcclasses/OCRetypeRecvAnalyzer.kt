package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor

class OCRetypeRecvAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {

    lateinit var program: Program
    lateinit var log: MessageLog

    companion object {
        const val NAME = "Objective-C: Retype Receiver Arguments"
        const val DESCRIPTION = "Retype receiver arguments for class methods."
        val PRIORITY = AnalysisPriority.FUNCTION_ANALYSIS.after()
    }

    init {
        priority = PRIORITY
        setPrototype()
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program

        val objcConstSection = program.memory.getBlock("__objc_const")
        return objcConstSection != null
    }

    override fun added(program: Program, addresses: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        this.log = log
        val classMethods = getClassMethods()

        program.withTransaction<Exception>("Apply receiver types to class methods.") {
            classMethods.forEach { (typedef, methods) ->
                println("CLASS ${typedef.name}")

                for (method in methods) {
                    println("   METHOD ${method.name}")

                    if (method.parameterCount == 0) {
                        continue
                    }

                    val param = method.getParameter(0)
                    if (!param.isAutoParameter) {
                        param.setDataType(PointerDataType(typedef), SourceType.ANALYSIS)
                    }
                }
            }
        }

        return true
    }

    private fun getClassMethods(): HashMap<DataType, List<Function>> {
        val dtCategory = CategoryPath("/GA_OBJC")

        val classTypes = program.dataTypeManager.getCategory(dtCategory).dataTypes

        val cns = program.symbolTable.classNamespaces.asSequence().toList()

        val result = hashMapOf<DataType, List<Function>>()
        for (entry in classTypes) {
            val klass = cns.firstOrNull {
                it.name.toString() == entry.name
            } ?: continue

            val fcns = program.functionManager.getFunctions(klass.body, true)

            result[entry] = fcns.toList()
        }

        return result
    }

}
