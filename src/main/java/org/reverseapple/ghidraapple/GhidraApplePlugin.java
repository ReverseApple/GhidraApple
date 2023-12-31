package org.reverseapple.ghidraapple;


import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = "GhidraObjC",
        category = "Objective-C",
        shortDescription = "short desc",
        description = "long desc"
)
public class GhidraApplePlugin extends ProgramPlugin {

    Program program;

    public GhidraApplePlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    public void init() {
        super.init();

    }



}
