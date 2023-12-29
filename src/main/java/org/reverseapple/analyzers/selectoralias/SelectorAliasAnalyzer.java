package org.reverseapple.analyzers.selectoralias;

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

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
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        return false;
    }

    @Override
    public AnalysisOptionsUpdater getOptionsUpdater() {
        return super.getOptionsUpdater();
    }
}
