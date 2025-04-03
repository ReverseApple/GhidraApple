package lol.fairplay.ghidraapple.actions

import ghidra.framework.cmd.BackgroundCommand
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Library
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.externalBlock
import lol.fairplay.ghidraapple.analysis.utilities.updateFunctionSignatureFromSelector
import lol.fairplay.ghidraapple.db.ExternalObjectiveCClass
import lol.fairplay.ghidraapple.db.ObjectiveCClass
import lol.fairplay.ghidraapple.db.Selector

class CreateObjCMethodThunkCmd(
    val cls: ExternalObjectiveCClass,
    val methodName: Selector,
    val sourceType: SourceType = SourceType.IMPORTED,
) : BackgroundCommand<Program>() {
    var function: Function? = null

    private fun createExternalClass(
        program: Program,
        cls: ObjectiveCClass,
    ): GhidraClass {
        //
        // We need to find the library that this class comes from
        val externalClassSymbol =
            with(program.externalManager) {
                externalLibraryNames
                    // For each collection of external locations
                    .map { getExternalLocations(it).asSequence().toList() }
                    // Find the one that has a symbol like `_OBJC_CLASS_$_${cls.name}`
                    .mapNotNull { locations ->
                        locations.singleOrNull { it.label == "_OBJC_CLASS_\$_${cls.name}" }
                    }.single()
            }
        val externalLibrary: Library = externalClassSymbol.parentNameSpace as Library
        val classNameSpace: GhidraClass = program.symbolTable.createClass(externalLibrary, cls.name, sourceType)
        externalClassSymbol.symbol.setNamespace(classNameSpace)
        return classNameSpace
    }

    /**
     * If the external class has already been created, but the [ObjectiveCClass] data object is stale,
     * then we don't need to create a [GhidraClass] and can just use the existing one
     */
    private fun getOrCreateExternalClass(
        program: Program,
        cls: ObjectiveCClass,
    ): GhidraClass {
        val existingNameSpace: GhidraClass? =
            program.symbolTable.classNamespaces
                .asSequence()
                .singleOrNull { it.name == cls.name }
        if (existingNameSpace != null) {
            if (existingNameSpace.parentNamespace is Library) {
                return existingNameSpace
            } else {
                throw IllegalStateException("Existing class namespace is not part of a Library?")
            }
        } else {
            return createExternalClass(program, cls)
        }
    }

    override fun applyTo(
        program: Program,
        monitor: TaskMonitor,
    ): Boolean {
        val externalNamespace: GhidraClass =
            when {
                /** The class has no associated [GhidraClass] **/
                cls.namespace == null -> getOrCreateExternalClass(program, cls)
                /** The class has an associated [GhidraClass] and that [GhidraClass] is associated with a [Library] **/
                cls.namespace.parentNamespace is Library -> cls.namespace
                // Unexpected edge case
                else -> TODO("Unexpected edge case: parentNamespace is not Library, but ${cls.namespace.parentNamespace::class.simpleName}")
            }

        // Surprisingly there is no better way to find out if there is already a thunk function of that name in this specific namespace
        // Using program.symbolTable.getSymbols(selector, cls.namespace), results in the external symbol with an
        // address in EXTERNAL _address space_, and _not_ the thunk function inside the external _block_ (which is part of the 'ram' address space)
        val existingFunction =
            program.functionManager
                .getFunctions(true)
                .filter { it.isThunk }
                .filter { it.name == methodName && it.parentNamespace.name == cls.name }
                .firstOrNull()
//        val existingFunctionSymbol = program.symbolTable.getSymbols(externalNamespace).firstOrNull { it.name == methodName }
        if (existingFunction != null) {
            statusMsg = "Method $methodName already exists in class $externalNamespace"
            function = existingFunction
//            function = program.functionManager.getFunction(existingFunctionSymbol.id)
            return false
        }

        // TODO: Check if there is an existing thunk already
        val label = methodName
        val extLoc = program.externalManager.addExtFunction(externalNamespace, label, null, sourceType)
        program.functionManager
            .getFunctions(true)
            .filter { it.isThunk }
            .any()
        val thunkedFunction = extLoc.function

        // Create a thunk function with the name of the selector
        val address = getNextAddressInExtSpace(program)
        val function =
            program.functionManager.createThunkFunction(
                methodName,
                program.globalNamespace,
                address,
                AddressSet(address),
                thunkedFunction,
                sourceType,
            )
        this.function = function
        if (function == null) {
            TODO()
        }
        updateFunctionSignatureFromSelector(
            function,
            methodName,
            cls.classPointerType,
            SourceType.IMPORTED,
        )
        return true
    }

    /**
     * Adapted from [ghidra.app.plugin.core.memory.ExpandBlockModel.ExpandBlockCmd.applyTo]
     */
    private fun getNextAddressInExtSpace(program: Program): Address {
        val externalBlock = program.memory.externalBlock
        val newEntryAddress = externalBlock.end.add(1)
        val newBlock = program.memory.createBlock(externalBlock, externalBlock.name + ".exp", newEntryAddress, 0x8)
        val mergedBlock = program.memory.join(externalBlock, newBlock)
        mergedBlock.name = externalBlock.name
        return newEntryAddress
    }

    override fun getName(): String = "Create Objective-C Method Thunk"
}
