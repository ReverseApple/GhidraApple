package lol.fairplay.ghidraapple.decompiler

import ghidra.app.plugin.core.decompile.DecompilePlugin
import ghidra.app.plugin.core.decompile.DecompilerProvider
import ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider


fun getDecompilerProvider(plugin: DecompilePlugin): DecompilerProvider? {
    return try {
        val field = plugin.javaClass.declaredFields.find { it.type == PrimaryDecompilerProvider::class.java } ?: return null

        field.isAccessible = true
        val provider = field.get(plugin)
        field.isAccessible = false

        provider as? DecompilerProvider
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }
}
