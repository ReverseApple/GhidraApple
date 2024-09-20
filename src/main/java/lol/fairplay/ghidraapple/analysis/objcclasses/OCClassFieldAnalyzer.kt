package lol.fairplay.ghidraapple.analysis.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.address.GenericAddress
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.*;
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor

private data class IVarField(val name: String, val type: String, val size: Int, val offset: Int)
private data class IVarFieldList(val classSymbol: Symbol, val ivars: List<IVarField>)

class OCClassFieldAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER) {

    lateinit var program: Program
    lateinit var log: MessageLog

    companion object {
        const val NAME = "Objective-C Class Field Analyzer"
        const val DESCRIPTION = "write this later"
        val PRIORITY = AnalysisPriority.DATA_ANALYSIS
    }

    init {
        priority = PRIORITY
        setPrototype()
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program
        return tryResolveNamespace("objc", "ivar_list_t")?.let { true } == true
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        this.log = log

        val idDataType = program.dataTypeManager.getDataType("/_objc2_/ID")
        val fieldLists = getIVarListsInAddressSet(set) ?: return false

        program.withTransaction<Exception>("Applying fields...") {
            for (it in fieldLists) {
                val definedClassStruct = tryResolveDefinedStruct(it.classSymbol.name) as Structure?
                if (definedClassStruct == null) {
                    log.appendMsg("Couldn't find defined structure for ${it.classSymbol.name} ivar list.")
                    continue
                }

                it.ivars.forEach { field ->
                    val fieldType = field.type.let {
                        tryResolveDefinedStruct(it) ?: idDataType
                    }

                    definedClassStruct.add(fieldType, field.size.toInt(), field.name, null)
                }
            }
        }


        return true
    }

    private fun getIVarListsInAddressSet(set: AddressSetView): List<IVarFieldList>? {
        val ivarNamespace = tryResolveNamespace("objc", "ivar_list_t") ?: return null

        val ivarNamespaceName = ivarNamespace.getName(true)

        val ivarLists = program.listing.getDefinedData(set, true)
            .filter { data ->
                val primarySymbol = data.primarySymbol
                val parentNamespace = primarySymbol?.parentNamespace
                primarySymbol != null &&
                        parentNamespace != null &&
                        parentNamespace.getName(true) == ivarNamespaceName
            }
            .mapNotNull { data -> parseIVarFieldList(data) }
            .toList()

        return if (ivarLists.isNotEmpty()) ivarLists else null
    }

    private fun parseIVarFieldList(data: Data): IVarFieldList? {
        val definedClassStruct = data.primarySymbol
        val ivFields = mutableListOf<IVarField>()

        if (data.numComponents <= 2)
            return null

        for (i in 2 until data.numComponents) {

            // struct ivar_t {
            //    Off  Type      Len Name
            //    0    qword*    8   offset      ""
            //    8    string*   8   name        ""
            //    16   string*   8   type        ""
            //    24   dword     4   alignment   ""
            //    28   dword     4   size        ""
            // }

            if (data.getComponent(i).dataType.name != "ivar_t")
                continue

            val fields = (0 .. data.getComponent(i).numComponents - 1).map {
                data.getComponent(i).getComponent(it)
            }

            // There's gotta be a better way to do this...
            val ivfName = program.listing.getDataAt(fields[1].value as GenericAddress?).value as String
            val ivfType = program.listing.getDataAt(fields[2].value as GenericAddress?).value as String
            val ivfSize = (fields[4].value as Scalar).value.toInt()
            val ivfOffset = (program.listing.getDataAt((fields[0].value as GenericAddress)).value as Scalar).value.toInt()

            ivFields.add(IVarField(ivfName, ivfType, ivfSize, ivfOffset))
        }

        return IVarFieldList(definedClassStruct, ivFields)
    }

    private fun tryResolveDefinedStruct(name: String): DataType? {
        val category = CategoryPath("/GA_OBJC")
        return program.dataTypeManager.getDataType(category, "struct_${name}")
    }

    private fun tryResolveNamespace(vararg fqnParts: String): Namespace?  {
        // todo: move this to a utilities file eventually.
        var ns = program.globalNamespace
        for (part in fqnParts) {
            ns = program.symbolTable.getNamespace(part, ns) ?: return null
        }
        return ns
    }
}
