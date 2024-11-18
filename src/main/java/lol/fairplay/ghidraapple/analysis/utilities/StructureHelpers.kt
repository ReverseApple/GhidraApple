package lol.fairplay.ghidraapple.analysis.utilities


import ghidra.program.model.address.GenericAddress
import ghidra.program.model.listing.Data
import ghidra.program.model.scalar.Scalar

object StructureHelpers {

    // allow components of the data object to be accessed using the subscript operator.
    operator fun Data.get(index: Int): Data {
        return this.getComponent(index)
    }

    fun Data.longValue(signed: Boolean = true): Long {
        val v = this.value
        return if (v is Scalar) {
            if (signed) v.signedValue else v.unsignedValue
        } else if (v is GenericAddress) {
            if (signed) v.offset else v.unsignedOffset
        } else {
            throw IllegalArgumentException("Unexpected value type: $v")
        }
    }

    /**
     * Return a list of all components in a Data object.
     */
    fun Data.getComponents(): List<Data> {
        return (0..<this.numComponents).map { this.getComponent(it) }
    }

    /**
     * Return the value of type `T` pointed to by `value`
     */
    fun <T> Data.deref(): T {
        // program.listing.getDataAt(fields[1].value as GenericAddress?).value as String
        return this.program.listing.getDataAt(this.value as GenericAddress?).value as T
    }

    fun Data.derefUntyped(): Data {
        return this.program.listing.getDataAt(this.value as GenericAddress?)
    }
}

