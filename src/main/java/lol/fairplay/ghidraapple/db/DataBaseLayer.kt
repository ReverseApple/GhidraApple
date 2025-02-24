package lol.fairplay.ghidraapple.db

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.util.LongPropertyMap
import ghidra.program.model.util.PropertyMapManager
import lol.fairplay.ghidraapple.analysis.utilities.addCollection
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import lol.fairplay.ghidraapple.analysis.utilities.toMap

typealias Selector = String

/**
 * We need to store various information in the Ghidra Database and retrieve it
 * The storage is implemented via [PropertyMapManager] interface provided via [Program.getUsrPropertyManager]
 *
 * The [PropertyMapManager] only provides storage for primitive types, or composite objects of primitives
 * so we provide this layer to turn this back into useful objects
 */
class DataBaseLayer(
    val program: Program,
) {
    companion object {
        private const val STATIC_DISPATCH_TABLE = "StaticCallTable"
        private const val ALLOCED_DISPATCH_TABLE = "AllocedCallTable"
        private const val TYPE_BOUND_TABLE = "TypeBoundTable"
        private const val SELECTOR_DATA = "SelectorData"
    }

    /**
     * TODO: should this also return the selector for stub calls?
     */
    fun getSelectorAtCallsite(addr: Address): Selector? {
        return program.usrPropertyManager.getStringPropertyMap(SELECTOR_DATA).get(addr)
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

    fun getAllocedReceiverAddrAtCallsite(addr: Address): Address? {
        val receiver =
            program.usrPropertyManager.getStringPropertyMap(ALLOCED_DISPATCH_TABLE)?.getString(addr)?.let {
                program.addressFactory.getAddress(it)
            }
        return receiver
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
}
