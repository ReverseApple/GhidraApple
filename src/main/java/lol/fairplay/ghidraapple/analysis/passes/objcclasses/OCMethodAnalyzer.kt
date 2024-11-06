package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

class OCMethodAnalyzer : AbstractAnalyzer(
    NAME,
    DESCRIPTION,
    AnalyzerType.DATA_ANALYZER
) {

    companion object {
        private const val NAME = "Objective-C Methods"
        private const val DESCRIPTION = "Analyze method signatures and apply types."
    }

    init {
        priority = OCClassFieldAnalyzer.PRIORITY.after()
        setSupportsOneTimeAnalysis()
        setPrototype()
    }

    override fun canAnalyze(program: Program?): Boolean {
        return super.canAnalyze(program)
    }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog
    ): Boolean {
        // Analyze all method list structures in an Objective-C binary.
        // Gather all members of: "objc::method_list_t::*"

        // If the entry contains a structure definition beginning with: "method_list_t_small_"
        //  - the list structure contains `method_small_t` definitions

        // Conversely, if the namespace entry contains a structure beginning with: "method_list_t_"
        //  - the list structure contains `method_t` definitions
        //  - following those entries, are `count` type encodings for each respective `method_t` entry.
        //    - these contiguous encoding pointers reference more descriptive types than those included in each
        //       `method_t` entry, under their respective `types` field.

        // Cursory research suggests that more informative signatures also exist for `method_small_t` entries. However,
        //  it is currently not clear how a method_small_t definition can be concretely and systematically related.

        // method_small_t types follow:
        /*
            // Note: __((relative)) denotes a relative pointer value.
            //  The absolute location for the pointed data can be computed with: (field_address + field_value)

            struct method_small_t {
                string * *32 __((relative)) name;
                string *32 __((relative)) types;
                string *32 __((relative)) imp;
            };
         */

        TODO("Not yet implemented")
    }
}
