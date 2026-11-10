package org.esperware.ghidramcp;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = "Ghidra Core",
        category = "Data",
        shortDescription = "Persistent Ghidra MCP",
        description = "Exposes the contract-v1 MCP tools over stdio from the owning Ghidra runtime.",
        servicesRequired = {ProgramManager.class})
public final class GhidraMCPPlugin extends ProgramPlugin {
    private GhidraMcpServer mcp;
    private GhidraSessionService sessions;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        try {
            ProgramManager programManager = tool.getService(ProgramManager.class);
            Project project = tool.getProject();
            sessions = new GhidraSessionService(programManager, project);
            sessions.setActiveProgram(currentProgram);
            mcp = new GhidraMcpServer(sessions);
        } catch (Exception failure) {
            Msg.showError(this, tool.getToolFrame(), "Ghidra MCP failed to start", failure.getMessage());
            Msg.error(this, "Ghidra MCP failed to start", failure);
        }
    }

    @Override
    protected void programActivated(ghidra.program.model.listing.Program program) {
        if (sessions != null) sessions.setActiveProgram(program);
    }

    @Override
    protected void programDeactivated(ghidra.program.model.listing.Program program) {
        if (sessions != null) sessions.setActiveProgram(currentProgram);
    }

    @Override
    protected void dispose() {
        if (mcp != null) mcp.close();
        super.dispose();
    }
}
