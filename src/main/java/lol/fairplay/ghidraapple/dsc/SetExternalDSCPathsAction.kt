package lol.fairplay.ghidraapple.dsc

import docking.action.MenuData
import ghidra.app.context.ProgramActionContext
import ghidra.app.context.ProgramContextAction
import ghidra.framework.main.AppInfo
import ghidra.framework.main.DataTreeDialog
import ghidra.framework.main.DataTreeDialog.CHOOSE_FOLDER
import ghidra.framework.model.DomainFolder
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.Library
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghidra.util.Msg

typealias SymbolName = String
typealias ProgramName = String

class SetExternalDSCPathsAction: ProgramContextAction("Set External DSC Paths", "DSC") {
    init {
        menuBarData = MenuData(arrayOf("DSC", "Set External DSC Paths"))
    }

    override fun actionPerformed(context: ProgramActionContext) {
        val dialog = DataTreeDialog(null, "Set DSC Root", CHOOSE_FOLDER)
        dialog.show()
        val dscRoot: DomainFolder = dialog.domainFolder ?: return
//        Msg.info(this, "Selected folder: ${dscRoot.name}")
        val projectPrefix = dscRoot.pathname
        context.program.withTransaction<Exception>("Set external programs") {
            context.program.externalManager.externalLibraryNames
                .filter { it.startsWith('/') }
                .forEach {
                    context.program.externalManager.setExternalPath(it, projectPrefix + it, false)
                }
        }
//        val project = AppInfo.getActiveProject()
//        val programs = with (context.program){
//            externalManager.externalLibraryNames
//                .map(externalManager::getExternalLibraryPath)
//                .map { project.projectData.getFile(it)}
//                .map {
//                    it.getDomainObject(this, false, false, null) as ProgramDB
//                }
//        }
//
//
//        val extLocation = context.program.externalManager.getUniqueExternalLocation(Library.UNKNOWN, "foo")
//        extLocation.setLocation()
//
//        val symbolMap = mutableMapOf<SymbolName, ProgramName>()
//        programs.forEach { externalProgram ->
//            externalProgram.externalSymbols.forEach {
//                symbolMap[it.name] = externalProgram.name
//            }
//        }
//
//
//            context.program.externalSymbols.forEach {
//                val sourceProgram = symbolMap[it.name]
//            }


    }
}


val Program.externalSymbols: List<Symbol>
    get() {
        return this.symbolTable.externalEntryPointIterator.map { this.symbolTable.getPrimarySymbol(it) }.toList()
    }
