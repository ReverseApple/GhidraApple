package org.reverseapple.ghidraapple.analyzers.selectoralias;

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.reverseapple.ghidraapple.utils.MachOCpuID;

public class SelectorAliasAnalyzer extends AbstractAnalyzer {

    public final static String NAME = "Selector Alias Concretization";
    public final static String DESCRIPTION = "Test";

    protected SelectorAliasAnalyzer(String name, String description, AnalyzerType type) {
        super(name, description, type);

        setDefaultEnablement(false);
        setPriority(AnalysisPriority.LOW_PRIORITY);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        // todo: consider checking for presence of certain relevant Objective-C sections.

        if (program.getExecutableFormat().equals(MachoLoader.MACH_O_NAME)) {
            try {
                MachOCpuID cpuArch = MachOCpuID.getCPU(program);

                if (cpuArch == MachOCpuID.AARCH64 || cpuArch == MachOCpuID.AARCH64E)
                    return true;

            } catch (MemoryAccessException e) {
                return false;
            }
        }

        return false;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        return false;
    }

    @Override
    public AnalysisOptionsUpdater getOptionsUpdater() {
        return super.getOptionsUpdater();
    }
}
