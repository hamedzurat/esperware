package org.esperware.ghidramcp;

import com.google.gson.Gson;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Registers the student-facing MCP tools. */
final class GhidraMcpServer implements AutoCloseable {
    private final McpSyncServer server;
    private final Gson gson = new Gson();

    GhidraMcpServer(GhidraSessionService sessions) {
        StdioServerTransportProvider transport = new StdioServerTransportProvider(McpJsonDefaults.getMapper());
        server = McpServer.sync(transport)
                .serverInfo("ghidraMCP", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(false).build())
                .build();
        for (SyncToolSpecification tool : tools(sessions)) server.addTool(tool);
    }

    private List<SyncToolSpecification> tools(GhidraSessionService sessions) {
        List<SyncToolSpecification> result = new ArrayList<>();
        result.add(tool("program_session", "Open, inspect, or close the one active program session.",
                schema(List.of("contract_version", "action"), Map.of(
                        "contract_version", integer(), "action", enumeration("open", "status", "close"),
                        "program", string(), "session_id", string(), "generation", integer(),
                        "expected_revision", integer())), sessions::programSession));
        result.add(tool("inspect_function", "Inspect one function, bounded pseudocode, callers, callees, xrefs, revision-bound variables, and referenced globals.",
                schema(List.of("contract_version", "session_id", "generation", "expected_revision", "function_address"), Map.of(
                        "contract_version", integer(), "session_id", string(), "generation", integer(),
                        "expected_revision", integer(), "function_address", string(), "cursor", string())), sessions::inspect));
        result.add(tool("search_pseudocode", "Find functions by name, signature, or decompiled pseudocode text.",
                schema(List.of("contract_version", "session_id", "generation", "expected_revision", "query", "match_in"), Map.of(
                        "contract_version", integer(), "session_id", string(), "generation", integer(),
                        "expected_revision", integer(), "query", string(),
                        "match_in", enumeration("name", "signature", "pseudocode", "all"), "cursor", string())), sessions::searchPseudocode));
        result.add(tool("search_types", "Find existing program types; structures include bounded field layout details.",
                schema(List.of("contract_version", "session_id", "generation", "expected_revision", "query"), Map.of(
                        "contract_version", integer(), "session_id", string(), "generation", integer(),
                        "expected_revision", integer(), "query", string(), "cursor", string())), sessions::searchTypes));
        result.add(tool("edit_function", "Edit a function, local variable, or referenced global. For variable/global targets, use the matching revision-bound reference from inspect_function; types accept an existing Ghidra type path or type expression.",
                schema(List.of("contract_version", "session_id", "generation", "expected_revision", "target", "change"), Map.of(
                        "contract_version", integer(), "session_id", string(), "generation", integer(),
                        "expected_revision", integer(), "target", objectSchema(Map.of(
                                "kind", enumeration("function", "variable", "global"), "function_address", string(),
                                "variable_ref", string(), "global_ref", string()), List.of("kind", "function_address")),
                        "change", objectSchema(Map.of("kind", enumeration("rename", "comment", "type", "signature"), "value", string()), List.of("kind", "value")))), sessions::edit));
        result.add(tool("save_program", "Save live program changes without advancing the revision.",
                schema(List.of("contract_version", "session_id", "generation", "expected_revision"), Map.of(
                        "contract_version", integer(), "session_id", string(), "generation", integer(), "expected_revision", integer())), sessions::save));
        result.add(tool("revert_last_edit", "Revert the latest eligible MCP edit as a new program revision.",
                schema(List.of("contract_version", "session_id", "generation", "expected_revision", "edit_id"), Map.of(
                        "contract_version", integer(), "session_id", string(), "generation", integer(),
                        "expected_revision", integer(), "edit_id", string())), sessions::revert));
        return result;
    }

    private SyncToolSpecification tool(String name, String description,
            Map<String, Object> schema, ToolHandler handler) {
        return SyncToolSpecification.builder()
                .tool(McpSchema.Tool.builder(name, schema).description(description).build())
                .callHandler((exchange, request) -> {
                    try {
                        return success(handler.call(request.arguments()));
                    } catch (Contract.McpFault fault) {
                        Map<String, Object> error = new LinkedHashMap<>();
                        error.put("ok", false);
                        Map<String, Object> detail = new LinkedHashMap<>();
                        detail.put("code", fault.code);
                        detail.put("message", fault.getMessage());
                        error.put("error", detail);
                        if (fault.currentRevision != null) {
                            detail.put("current_revision", fault.currentRevision);
                            if ("STALE_REVISION".equals(fault.code)) detail.put("retry", "reinspect, then decide whether to retry");
                        }
                        return failure(error);
                    } catch (Exception exception) {
                        Msg.error(this, "Ghidra MCP tool failed", exception);
                        return failure(Map.of("ok", false, "error", Map.of(
                                "code", "OPERATION_FAILED", "message", safeMessage(exception))));
                    }
                }).build();
    }

    private Map<String, Object> schema(List<String> required, Map<String, Object> properties) {
        return Map.of("type", "object", "properties", properties, "required", required, "additionalProperties", false);
    }

    private Map<String, Object> objectSchema(Map<String, Object> properties, List<String> required) {
        return schema(required, properties);
    }

    private Map<String, Object> string() { return Map.of("type", "string"); }
    private Map<String, Object> integer() { return Map.of("type", "integer"); }
    private Map<String, Object> enumeration(String... values) { return Map.of("type", "string", "enum", List.of(values)); }

    private McpSchema.CallToolResult success(Map<String, Object> value) {
        return McpSchema.CallToolResult.builder()
                .content(List.of(new McpSchema.TextContent(gson.toJson(value))))
                .build();
    }

    private McpSchema.CallToolResult failure(Map<String, Object> value) {
        return McpSchema.CallToolResult.builder()
                .content(List.of(new McpSchema.TextContent(gson.toJson(value))))
                .isError(true)
                .build();
    }

    private static String safeMessage(Exception exception) {
        return exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
    }

    @Override public void close() { server.close(); }

    @FunctionalInterface
    private interface ToolHandler {
        Map<String, Object> call(Map<String, Object> arguments) throws Exception;
    }
}
