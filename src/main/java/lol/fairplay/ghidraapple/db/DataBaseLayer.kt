package lol.fairplay.ghidraapple.db

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock.EXTERNAL_BLOCK_NAME
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.util.LongPropertyMap
import ghidra.program.model.util.PropertyMapManager
import lol.fairplay.ghidraapple.analysis.objectivec.GhidraTypeBuilder.Companion.OBJC_CLASS_CATEGORY
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.passes.selectortrampoline.SelectorTrampolineAnalyzer.Companion.STUB_NAMESPACE_NAME
import lol.fairplay.ghidraapple.analysis.utilities.addCollection
import lol.fairplay.ghidraapple.analysis.utilities.getLabelAtAddress
import lol.fairplay.ghidraapple.analysis.utilities.getOrCreateLongPropertyMap
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import lol.fairplay.ghidraapple.analysis.utilities.toMap
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass

typealias Selector = String

/**
 * We need to store various information in the Ghidra Database and retrieve it
 * The storage is implemented via [PropertyMapManager] interface provided via [Program.getUsrPropertyManager]
 *
 * The [PropertyMapManager] only provides storage for primitive types, or composite objects of primitives
 * so we provide this layer to turn this back into useful objects
 *
 * The DatabaseLayer does not have any internal state beyond caches. It is a thin wrapper around the [Program]
 * to make it easier to access information. It is not responsible for the correctness of the data stored in the database,
 * nor does it provide any sort of cache invalidation.
 *
 *
 */
class DataBaseLayer(
    val program: Program,
) {
    companion object {
        private const val STATIC_DISPATCH_TABLE = "StaticCallTable"
        private const val ALLOCED_DISPATCH_TABLE = "AllocedCallTable"
        private const val TYPE_BOUND_TABLE = "TypeBoundTable"
        private const val SELECTOR_DATA = "SelectorData"
        private const val PARAM_DISPATCH_TABLE = "ParamDispatchTable"
    }

    /**
     * TODO: should this also return the selector for stub calls?
     */
    fun getSelectorAtCallsite(addr: Address): Selector? {
        return program.usrPropertyManager.getStringPropertyMap(SELECTOR_DATA)?.get(addr)
    }

    fun findSelectorCallsites(selector: Selector): Set<Address> {
        // Get callsites to dispatch methods with that selector
        val selectorMap = program.usrPropertyManager.getStringPropertyMap(SELECTOR_DATA)
        val msgSendCallsites = selectorMap.toMap().filterValues { it == selector }.keys
        // Get all callsites for the stub of the selector
        val stubNamespace = program.symbolTable.getNamespace(STUB_NAMESPACE_NAME, program.globalNamespace)
        val stubSymbol = program.symbolTable.getSymbol(selector, null, stubNamespace)
        val stubCallsites = stubSymbol.references.map { it.fromAddress }.toSet()

        return msgSendCallsites + stubCallsites

    }

    fun getStaticReceiverAddrAtCallsite(addr: Address): Address? {
        val receiver =
            program.usrPropertyManager.getStringPropertyMap(STATIC_DISPATCH_TABLE)?.getString(addr)?.let {
                program.addressFactory.getAddress(it)
            }
        return receiver
    }

    fun getStaticReceiverSymbolAtCallsite(addr: Address): Symbol? {
        val addr = getStaticReceiverAddrAtCallsite(addr)?.toDefaultAddressSpace(program)
        return addr?.let { program.symbolTable.getPrimarySymbol(it) }
    }

    fun getStaticReceiverClassAtCallsite(addr: Address): ObjectiveCClass? {
        val symbol = getStaticReceiverSymbolAtCallsite(addr)
        return symbol?.let { getClassFromSymbol(it) }
    }


    fun getAllocedReceiverAddrAtCallsite(addr: Address): Address? {
        val receiver =
            program.usrPropertyManager.getStringPropertyMap(ALLOCED_DISPATCH_TABLE)?.getString(addr)?.let {
                program.addressFactory.getAddress(it)
            }
        return receiver
    }

    fun getAllocedReceiverClassAtCallsite(addr: Address): ObjectiveCClass? {
        val symbol = getAllocedReceiverSymbolAtCallsite(addr)
        return symbol?.let { getClassFromSymbol(it) }
    }

    fun getAllocedReceiverSymbolAtCallsite(addr: Address): Symbol? {
        val addr = getAllocedReceiverAddrAtCallsite(addr)?.toDefaultAddressSpace(program)
        return addr?.let { program.symbolTable.getPrimarySymbol(it) }
    }

    fun getAllocedReceiverClassnameAtCallsite(addr: Address): String? {
        val symbol = getAllocedReceiverSymbolAtCallsite(addr)
        return symbol?.name?.removePrefix("_OBJC_CLASS_\$_")
    }

    fun getTypeBoundAtCallsite(addr: Address): DataType? {
        val typeId = program.usrPropertyManager.getLongPropertyMap(TYPE_BOUND_TABLE)?.get(addr)
        return typeId?.let { program.dataTypeManager.getDataType(it) }
    }

    fun getParamReceiverAtCallsite(addr: Address): Register? {
        val registerOffset = program.usrPropertyManager.getLongPropertyMap(PARAM_DISPATCH_TABLE)?.get(addr) ?: return null
        val registerAddress = program.language.addressFactory.registerSpace.getAddress(registerOffset)
        val register = program.language.getRegister(registerAddress, 8)
        return register
    }

    fun getAllTypeBounds(): Map<Address, DataType>? {
        val typeBoundData: LongPropertyMap? = program.usrPropertyManager.getLongPropertyMap(TYPE_BOUND_TABLE)
        if (typeBoundData == null) {
            return null
        }

        return typeBoundData.toMap().mapValues { (k, v) -> program.dataTypeManager.getDataType(v) }.toMap()
    }

    fun addSelectors(selectors: Map<Address, Selector?>) {
        val propMap =
            program.usrPropertyManager.getStringPropertyMap(SELECTOR_DATA)
                ?: program.usrPropertyManager.createStringPropertyMap(SELECTOR_DATA)
        propMap.addCollection(selectors.map { (addr, selector) -> addr to selector })
    }

    fun addStaticReceivers(staticReceivers: Map<Address, Address?>) {
        val propMap =
            program.usrPropertyManager.getStringPropertyMap(STATIC_DISPATCH_TABLE)
                ?: program.usrPropertyManager.createStringPropertyMap(STATIC_DISPATCH_TABLE)
        propMap.addCollection(staticReceivers.map { (ref, clsAddr) -> ref to clsAddr.toString() })
    }

    fun addTypeBounds(typeBounds: Map<Address, DataType?>) {
        val propMap =
            program.usrPropertyManager.getLongPropertyMap(TYPE_BOUND_TABLE)
                ?: program.usrPropertyManager.createLongPropertyMap(TYPE_BOUND_TABLE)
        propMap.addCollection(typeBounds.map { (ref, dataType) -> ref to program.dataTypeManager.getID(dataType) })
    }

    fun addAllocedReceivers(allocedReceivers: Map<Address, Address?>) {
        val propMap =
            program.usrPropertyManager.getStringPropertyMap(ALLOCED_DISPATCH_TABLE)
                ?: program.usrPropertyManager.createStringPropertyMap(ALLOCED_DISPATCH_TABLE)

        propMap.addCollection(allocedReceivers.map { (ref, clsAddr) -> ref to clsAddr.toString() })
    }

    fun addParamReceivers(paramDispatchTable: Map<Address, Address?>) {
        val propMap = program.usrPropertyManager.getOrCreateLongPropertyMap(PARAM_DISPATCH_TABLE)
        propMap.addCollection(paramDispatchTable.map { (ref, clsAddr) -> ref to clsAddr?.offset })
    }


    fun getClassNameFromSymbol(symbol: Symbol): String {
        return when(program.memory.getBlock(symbol.address).name) {
            "__got" -> {
                // This is a global offset table entry, which are named like `PTR__OBJC_CLASS_$_CWWiFiClient_100155330`
                // where `100155330` is the address inside the __got section
                symbol.name.removePrefix("PTR__OBJC_CLASS_\$_").split('_').first()
            }
            "__objc_data" -> symbol.name
            EXTERNAL_BLOCK_NAME -> {
                // Named like `_OBJC_CLASS_$_CLCircularRegion`
                symbol.name.removePrefix("_OBJC_CLASS_\$_")
            }
            else -> throw IllegalArgumentException("Unexpected kind of symbol: ${symbol.name} from ${symbol.address}")

        }
    }

    /**
     * Takes a symbol like `_OBJC_CLASS_$_CLCircularRegion` or `PTR__OBJC_CLASS_$_NSMutableDictionary_1001553d0`
     */
    fun getClassFromSymbol(symbol: Symbol): ObjectiveCClass {
        val className = getClassNameFromSymbol(symbol)
        val layout = program.dataTypeManager.getDataType("/GA_OBJC/$className") as Structure
        val classStructLocation = getAddressForClassName(className)
//        val namespace = program.symbolTable.classNamespaces.asSequence().singleOrNull { it.name == className }
        val namespace = symbolToClassMap[className]
        return ObjectiveCClass(classStructLocation, namespace, layout, null)
    }

    val symbolToClassMap: Map<String, GhidraClass> by lazy {
        program.symbolTable.classNamespaces.asSequence().associateBy { it.name }
    }

    val classParser: StructureParsing by lazy {
        StructureParsing(program)
    }

    private fun getAddressForClassName(className: String): Address {
        // Two scenarios:
        // 1. There is symbol with a name starting with `_OBJC_CLASS_$_`
        program.symbolTable.getSymbols("_OBJC_CLASS_\$_$className").singleOrNull { !it.isExternal }?.let {
            return it.address
        }
        // 2. There is a symbol in the `objc::class_t` namespace
        // In rare cases there are _two_ symbols for the same class, one is the metaclass of the other
        getInternalClassSymbols().firstOrNull() { it.name == className }?.let {
            return it.address
        }

        throw IllegalArgumentException("Could not find class $className")
    }

    private fun getInternalClassSymbols(): Set<Symbol> {
        val objcNamespace = program.symbolTable.getNamespace("objc", program.globalNamespace)
        val classTNamespace = program.symbolTable.getNamespace("class_t", objcNamespace)
        return program.symbolTable.getSymbols(classTNamespace).toSet()
    }

    /**
     * Get the class for a given address
     * this can include GOT addresses
     *
     * or "constant" addresses
     */
    fun getClassForAddress(address: Address): ObjectiveCClass {
        val symbol: Symbol =
            program.symbolTable.getPrimarySymbol(
                if (address.isConstantAddress) {
                    address.toDefaultAddressSpace(program)
                } else {
                    address
                },
            ) ?: throw IllegalArgumentException("No symbol at address $address")
        return getClassFromSymbol(symbol)
    }

    fun getClassForDataType(dataType: DataType): ObjectiveCClass? {
        val className = dataType.name
        val layout = dataType as Structure
        val classStructLocation = getAddressForClassName(className)
        val namespace = program.symbolTable.classNamespaces.asSequence().singleOrNull { it.name == className }
        val metaData = classParser.parseClass(classStructLocation)
        return ObjectiveCClass(classStructLocation, namespace, layout, metaData)
    }

    /**
     * Decide if a dataType belongs to an Objective-C class that is internal to the program or external
     * For now this is just a heuristic based on the size of the type
      */
    fun isTypeInternal(dataType: DataType): Boolean {
        return dataType.categoryPath == OBJC_CLASS_CATEGORY && !dataType.isZeroLength
    }

}


/**
 *
 * Our container object for a class
 *
 * It should encapsulate all the ways in which Ghidra represents a class in various contexts plus our own metadata
 *
 *
 * @property namespace The namespace of the class, if it exists
 * @property classStructLocation The address of the class struct, if it is in the local [Program]
 */
data class ObjectiveCClass(
    val classStructLocation: Address,
    val namespace: GhidraClass?,
    val layout: Structure,
    val metadata: OCClass?,
) {

    /**
     * Returns a pointer type to the underlying class layout struct
     *
     * This is used for typing variables and parameters
     */
    val classPointerType: Pointer
        get() = PointerDataType(layout)


    val name: String
        get() = namespace?.name ?: layout.name

    fun isPartOfProgram(program: Program): Boolean {
        return program.memory.contains(classStructLocation) && !program.memory.isExternalBlockAddress(this.classStructLocation)
    }
}
