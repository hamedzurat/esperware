package org.esperware.ghidramcp;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import java.nio.file.Path;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = "CodeViewer",
        category = "Data",
        shortDescription = "Persistent Ghidra MCP",
        description = "Exposes the contract-v1 MCP tools over stdio from the owning Ghidra runtime.",
        servicesRequired = {ProgramManager.class},
        servicesProvided = {HypothesisEvents.class})
public final class GhidraMCPPlugin extends ProgramPlugin implements HypothesisEvents {
    private GhidraMcpServer mcp;
    private HypothesisEventStore hypothesisStore;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        try {
            String configuredStore = System.getenv("GHIDRA_MCP_STORE");
            Path storePath = configuredStore == null || configuredStore.isBlank()
                    ? Path.of(System.getProperty("user.home"), ".ghidra", "ghidraMCP", "hypotheses.sqlite")
                    : Path.of(configuredStore);
            hypothesisStore = new HypothesisEventStore(storePath);
            ProgramManager programManager = tool.getService(ProgramManager.class);
            Project project = tool.getProject();
            GhidraSessionService sessions = new GhidraSessionService(programManager, project);
            mcp = new GhidraMcpServer(sessions);
        } catch (Exception failure) {
            Msg.showError(this, tool.getToolFrame(), "Ghidra MCP failed to start", failure.getMessage());
            Msg.error(this, "Ghidra MCP failed to start", failure);
        }
    }

    /** Trusted harness integration; intentionally not registered as an MCP tool. */
    public HypothesisEventStore hypothesisStore() {
        return hypothesisStore;
    }

    @Override
    public java.util.List<java.util.Map<String, Object>> recordHypothesisEvents(
            String runId, java.util.List<java.util.Map<String, Object>> events, String editId) throws Exception {
        return requireHypothesisStore().recordHypothesisEvents(runId, events, editId);
    }

    @Override
    public void linkEdit(String runId, String editId, java.util.List<String> hypothesisIds) throws Exception {
        requireHypothesisStore().linkEdit(runId, editId, hypothesisIds);
    }

    @Override
    public java.util.Map<String, Object> activeSnapshot(String runId, long revision) throws Exception {
        return requireHypothesisStore().activeSnapshot(runId, revision);
    }

    @Override
    public java.util.List<java.util.Map<String, Object>> history(String runId, String hypothesisId) throws Exception {
        return requireHypothesisStore().history(runId, hypothesisId);
    }

    private HypothesisEventStore requireHypothesisStore() {
        if (hypothesisStore == null) throw new IllegalStateException("Hypothesis store is not initialized");
        return hypothesisStore;
    }

    @Override
    protected void dispose() {
        if (mcp != null) mcp.close();
        if (hypothesisStore != null) {
            try {
                hypothesisStore.close();
            } catch (Exception failure) {
                Msg.error(this, "Could not close hypothesis store", failure);
            }
        }
        super.dispose();
    }
}
