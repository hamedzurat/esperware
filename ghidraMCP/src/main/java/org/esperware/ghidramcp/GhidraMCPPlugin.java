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
    private EditHistory history;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        try {
            ProgramManager programManager = tool.getService(ProgramManager.class);
            Project project = tool.getProject();
            String path = System.getenv().getOrDefault("GHIDRA_MCP_HISTORY_DB",
                    java.nio.file.Path.of(System.getProperty("user.home"), ".ghidra", "ghidraMCP", "history.sqlite").toString());
            int port = Integer.parseInt(System.getenv().getOrDefault("GHIDRA_MCP_HISTORY_PORT", "8765"));
            history = new EditHistory(java.nio.file.Path.of(path),
                    System.getenv().getOrDefault("GHIDRA_MCP_HISTORY_HOST", "127.0.0.1"), port);
            sessions = new GhidraSessionService(programManager, project, history);
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
        if (history != null) {
            try { history.close(); } catch (Exception failure) { Msg.error(this, "Could not close history", failure); }
        }
        super.dispose();
    }
}
