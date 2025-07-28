package lol.fairplay.ghidraapple.db

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Library
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock.EXTERNAL_BLOCK_NAME
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.util.LongPropertyMap
import ghidra.program.model.util.PropertyMapManager
import ghidra.util.Msg
import lol.fairplay.ghidraapple.analysis.objectivec.GhidraTypeBuilder.Companion.OBJC_CLASS_CATEGORY
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.passes.selectortrampoline.SelectorTrampolineAnalyzer.Companion.STUB_NAMESPACE_NAME
import lol.fairplay.ghidraapple.analysis.utilities.addCollection
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
    fun getSelectorAtCallsite(addr: Address): Selector? = program.usrPropertyManager.getStringPropertyMap(SELECTOR_DATA)?.get(addr)

    fun getSelectorMap(): Map<Address, Selector> = program.usrPropertyManager.getStringPropertyMap(SELECTOR_DATA).toMap()

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

    fun getStaticReceiverClassAtCallsite(addr: Address): ObjectiveCClass? {
        val classAddr = getStaticReceiverAddrAtCallsite(addr)?.toDefaultAddressSpace(program)
        return classAddr?.let { getClassForAddress(it) }
    }

    fun getAllocedReceiverAddrAtCallsite(addr: Address): Address? {
        val receiver =
            program.usrPropertyManager.getStringPropertyMap(ALLOCED_DISPATCH_TABLE)?.getString(addr)?.let {
                program.addressFactory.getAddress(it)
            }
        return receiver
    }

    fun getAllocedReceiverClassAtCallsite(callsite: Address): ObjectiveCClass? =
        getAllocedReceiverAddrAtCallsite(callsite)?.let {
            getClassForAddress(it)
        }

    fun getAllocedReceiverClassnameAtCallsite(callsite: Address): String? = getClassForAddress(callsite)?.name

    fun getTypeBoundAtCallsite(addr: Address): DataType? {
        val typeId = program.usrPropertyManager.getLongPropertyMap(TYPE_BOUND_TABLE)?.get(addr)
        return typeId?.let { program.dataTypeManager.getDataType(it) }
    }

    fun getParamReceiverAtCallsite(addr: Address): Register? {
        val registerOffset = program.usrPropertyManager.getLongPropertyMap(PARAM_DISPATCH_TABLE)?.get(addr) ?: return null
        val registerAddress =
            program.language.addressFactory.registerSpace
                .getAddress(registerOffset)
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

    fun getAllStaticReceiverCallsites(): Map<Address, String>? =
        program.usrPropertyManager.getStringPropertyMap(STATIC_DISPATCH_TABLE)?.toMap()

    fun getAllAllocedReceivers(): Map<Address, String>? = program.usrPropertyManager.getStringPropertyMap(ALLOCED_DISPATCH_TABLE)?.toMap()

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

    fun getClassNameFromSymbol(symbol: Symbol): String =
        when (program.memory.getBlock(symbol.address).name) {
            "__got" -> {
                // This is a global offset table entry, which are named like `PTR__OBJC_CLASS_$_CWWiFiClient_100155330`
                // where `100155330` is the address inside the __got section
                symbol.name
                    .removePrefix("PTR__OBJC_CLASS_\$_")
                    .split('_')
                    .first()
            }
            "__objc_data" -> symbol.name
            EXTERNAL_BLOCK_NAME -> {
                // Named like `_OBJC_CLASS_$_CLCircularRegion`
                symbol.name.removePrefix("_OBJC_CLASS_\$_")
            }
            else -> throw IllegalArgumentException("Unexpected kind of symbol: ${symbol.name} from ${symbol.address}")
        }

    fun isExternalClass(addr: Address): Boolean = addr.offset in externalClassAddresses

    fun isInternalClass(addr: Address): Boolean = addr.offset in internalClassAdresses

    val internalClassAdresses: Set<Long> by lazy {
        val objcNs = program.symbolTable.getNamespace("objc", program.globalNamespace)
        val classNameSpace = program.symbolTable.getNamespace("class_t", objcNs)
        program.symbolTable
            .getSymbols(classNameSpace)
            .map { it.address.offset }
            .toSet()
    }

    val externalClassAddresses: Set<Long> by lazy {
        program.symbolTable
            .getAllSymbols(false)
            .filter { it.name.startsWith("_OBJC_CLASS_") }
            .filter { program.memory.isExternalBlockAddress(it.address) }
            .map { it.address.offset }
            .toSet()
    }

    val symbolToClassMap: Map<String, GhidraClass> by lazy {
        program.symbolTable.classNamespaces
            .asSequence()
            .associateBy { it.name }
    }

    val classParser: StructureParsing by lazy {
        StructureParsing(program)
    }

    val classModelCache: MutableMap<Address, OCClass?> = mutableMapOf()

    private fun getAddressForClassName(className: String): Address? {
        // Two scenarios:
        // 1. There is symbol with a name starting with `_OBJC_CLASS_$_`
        program.symbolTable.getSymbols("_OBJC_CLASS_\$_$className").singleOrNull { !it.isExternal }?.let {
            return it.address
        }
        // 2. There is a symbol in the `objc::class_t` namespace
        // In rare cases there are _two_ symbols for the same class, one is the metaclass of the other
        getInternalClassSymbols().firstOrNull { it.name == className }?.let {
            return it.address
        }
        // There can be scenarios where a class type was created from e.g. a parsed type string, but this doesn't
        // require there to be a symbol and associated _address_ for this
        return null
//        throw IllegalArgumentException("Could not find class $className")
    }

    private fun getInternalClassSymbols(): Set<Symbol> {
        val objcNamespace = program.symbolTable.getNamespace("objc", program.globalNamespace)
        val classTNamespace = program.symbolTable.getNamespace("class_t", objcNamespace)
        return program.symbolTable.getSymbols(classTNamespace).toSet()
    }

    /**
     * Get the class for a given address
     * this can include GOT addresses
     * or "constant" addresses
     */
    fun getClassForAddress(address: Address): ObjectiveCClass? {
        if (address.offset == 0L) {
            return null
        }

        val ramAddress = program.addressFactory.defaultAddressSpace.getAddress(address.offset)
        val block = program.memory.getBlock(ramAddress)

        if (block?.name == "__got") {
            TODO()
        }
        val className =
            program.symbolTable
                .getPrimarySymbol(ramAddress)
                ?.name
                ?.removePrefix("_OBJC_CLASS_\$_") ?: return null
        when {
            // Classes don't start with underscores, this can happen if a global symbol is passed in
            className.startsWith("_") -> return null
            // TODO: CFConstantStringClassReference aren't supported for now
            //  because I don't know what the relevant underlying class for them is, and if it is imported?
            className.startsWith("cf_") -> return null
            className.startsWith("DAT_") -> return null
        }
        val layout: Structure =
            program.dataTypeManager.getDataType(OBJC_CLASS_CATEGORY, className) as Structure? ?: run {
                Msg.error(this, "Could not find class layout for $className")
                return null
            }
        val namespace: GhidraClass =
            program.symbolTable.classNamespaces
                .asSequence()
                .singleOrNull { it.name == className }
                ?: throw IllegalArgumentException("Could not find class namespace for $className")
        return when {
            isExternalClass(ramAddress) -> {
                /**
                 *  The [OCStructureAnalyzer] will have already parsed the class
                 */

                val library: Library = namespace.parentNamespace as Library
                ExternalObjectiveCClass(program, ramAddress, namespace, layout, library)
            }
            isInternalClass(ramAddress) -> {
                val metaData = classParser.parseClass(ramAddress)!!
                LocalObjectiveCClass(program, ramAddress, namespace, layout, metaData)
            }
            else -> null
        }
    }

    fun getClassForDataType(dataType: DataType): ObjectiveCClass? {
        val className = dataType.name
        val classStructLocation = getAddressForClassName(className) ?: return null
        return getClassForAddress(classStructLocation)
    }

    /**
     * Decide if a dataType belongs to an Objective-C class that is internal to the program or external
     * For now this is just a heuristic based on the size of the type
     */
    fun isTypeInternal(dataType: DataType): Boolean = dataType.categoryPath == OBJC_CLASS_CATEGORY && !dataType.isZeroLength
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
sealed class ObjectiveCClass {
    abstract val program: Program
//    abstract val classStructLocation: Address
    abstract val namespace: GhidraClass
    abstract val layout: Structure

    /**
     * Returns a pointer type to the underlying class layout struct
     *
     * This is used for typing variables and parameters
     */
    val classPointerType: Pointer
        get() = PointerDataType(layout)

    val name: String
        get() = namespace.name ?: layout.name
//
//    fun isPartOfProgram(program: Program): Boolean =
//        program.memory.contains(classStructLocation) && !program.memory.isExternalBlockAddress(this.classStructLocation)

    /**
     * Sometimes we just want to pretend that a class is associated with one adress, which makes it easier to save
     * in user properties.
     * This doesn't _always_ work, but it goes far enough
     */
    val classStructLocation: Address?
        get() {
            return when (this) {
                is LocalObjectiveCClass -> internalMetadataStructLocation
                is ExternalObjectiveCClass -> externalSymbolLocation
            }
    }
}

/**
 * A special case of [ObjectiveCClass] that is local to the [program] and has the class model available as [metaData]
 */
data class LocalObjectiveCClass(
    override val program: Program,
    val internalMetadataStructLocation: Address,
    override val namespace: GhidraClass,
    override val layout: Structure,
    val metaData: OCClass,
) : ObjectiveCClass() {
    override fun hashCode(): Int = program.hashCode() xor classStructLocation.hashCode() xor namespace.hashCode() xor layout.hashCode()
}

/**
 * A special case of [ObjectiveCClass] that is external to the [program] and has no class model available
 * The [namespace] is the [GhidraClass]
 */
data class ExternalObjectiveCClass(
    override val program: Program,
    // External Classes don't _always_ have an address, e.g. if they are only referenced by name in a type string
    val externalSymbolLocation: Address?,
    override val namespace: GhidraClass,
    override val layout: Structure,
    val library: Library,
) : ObjectiveCClass() {
    init {
        if (namespace.parentNamespace != library) {
            throw IllegalArgumentException("Namespace is not part of the library")
        }
    }
}
