package lol.fairplay.ghidraapple.analysis.utilities


import ghidra.program.model.listing.Data
import ghidra.program.model.scalar.Scalar

// allow components of the data object to be accessed using the subscript operator.
operator fun Data.get(index: Int): Data {
    return this.getComponent(index)
}

fun Data.longValue(signed: Boolean = true): Long {
    return (this.value as Scalar).let {
        return if (signed) it.signedValue else it.unsignedValue
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
    // Ensure that we account for relative pointers.
    TODO()
}

