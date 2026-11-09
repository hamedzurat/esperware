package org.esperware.ghidramcp;

import java.util.List;
import java.util.Map;

/** Ghidra service boundary for the trusted trajectory harness; never an MCP tool. */
public interface HypothesisEvents {
    List<Map<String, Object>> recordHypothesisEvents(
            String runId, List<Map<String, Object>> events, String editId) throws Exception;

    void linkEdit(String runId, String editId, List<String> hypothesisIds) throws Exception;

    Map<String, Object> activeSnapshot(String runId, long revision) throws Exception;

    List<Map<String, Object>> history(String runId, String hypothesisId) throws Exception;
}
