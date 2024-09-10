package lol.fairplay.ghidraapple;

import docking.action.builder.ActionBuilder;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.PcodeOp;
import lol.fairplay.ghidraapple.actions.ChooseMsgSendCalleeDialog;

import static lol.fairplay.ghidraapple.analysis.PCodeUtilsKt.getFunctionForPCodeCall;
import static lol.fairplay.ghidraapple.analysis.selectortrampoline.SelectorTrampolineAnalyzer.TRAMPOLINE_TAG;


//@formatter:off
@PluginInfo(
        status=PluginStatus.STABLE,
        packageName=GhidraApplePluginPackage.PKG_NAME,
        category=PluginCategoryNames.COMMON,
        shortDescription="",
        description=""
)
//@formatter:on
public class GhidraApplePlugin extends ProgramPlugin {
    public GhidraApplePlugin(PluginTool plugintool) {
        super(plugintool);
        setupActions();
    }

    private void setupActions() {
        new ActionBuilder("Choose msgSend Callee", "GhidraApple")
                .description("Choose msgSend Callee")
                .withContext(DecompilerActionContext.class)
                .enabledWhen(
                        ctx -> {
                            if (ctx.getLocation() instanceof DecompilerLocation location) {
                                var pCodeOp = location.getToken().getPcodeOp();
                                var optFunc = getFunctionForPCodeCall(ctx.getProgram(), pCodeOp);
                                if (optFunc.isEmpty()) {
                                    return false;
                                }
                                var func = optFunc.get();
                                if (func.getName().equals("objc_msgSend")) {
                                    return true;
                                }
                                for (FunctionTag tag: func.getTags()){
                                    if (tag.getName().equals(TRAMPOLINE_TAG)){
                                        return true;
                                    }
                                }
                            }
                            return false;
                        })
                .onAction(ctx ->
                    tool.showDialog(new ChooseMsgSendCalleeDialog(tool, currentProgram, ctx.getLocation().getAddress(), null))
                )
                .popupMenuPath(new String[] { "Choose Selector Callee" }  )
                .popupMenuGroup(GhidraApplePluginPackage.PKG_NAME)
                .buildAndInstall(tool);

    }

}
