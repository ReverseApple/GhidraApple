package lol.fairplay.ghidraapple.plugins;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.actions.ChooseMsgSendCalleeAction;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import lol.fairplay.ghidraapple.GhidraApplePluginPackage;


//@formatter:off
@PluginInfo(
        status=PluginStatus.STABLE,
        packageName=GhidraApplePluginPackage.PKG_NAME,
        category=PluginCategoryNames.COMMON,
        shortDescription="Objective-C Dynamic Dispatch",
        description="A plugin to help with Objective-C dynamic dispatches (msgSend family of functions)"
)
//@formatter:on
public class ObjectiveCDynamicDispatchPlugin extends ProgramPlugin {

    public ObjectiveCDynamicDispatchPlugin(PluginTool plugintool) {
        super(plugintool);
        setupActions();


    }

    private void setupActions() {
        tool.addAction(new ChooseMsgSendCalleeAction());
    }
}
