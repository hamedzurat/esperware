package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

/** Builds /mcp/rw (13 tools) and /mcp/ro (9 read-only tools) Streamable HTTP endpoints. */
final class McpEndpoints implements AutoCloseable {
    private static final String SERVER_NAME = "ghidraMCP";
    private static final String SERVER_VERSION = "0.2.0";

    record ToolDef(
            McpSchema.Tool tool,
            BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> handler) {}

    private final HttpServletStreamableServerTransportProvider rwTransport;
    private final HttpServletStreamableServerTransportProvider roTransport;
    private final McpSyncServer rwServer;
    private final McpSyncServer roServer;

    McpEndpoints(InspectService inspect, EditService edit) {
        var mapper = McpJsonDefaults.getMapper();

        rwTransport = HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(mapper)
                .mcpEndpoint("/mcp/rw")
                .keepAliveInterval(Duration.ofSeconds(30))
                .build();

        roTransport = HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(mapper)
                .mcpEndpoint("/mcp/ro")
                .keepAliveInterval(Duration.ofSeconds(30))
                .build();

        rwServer = buildServer(rwTransport, ApiError.AccessMode.READ_WRITE, inspect, edit);
        roServer = buildServer(roTransport, ApiError.AccessMode.READ_ONLY, inspect, edit);
    }

    HttpServletStreamableServerTransportProvider rwTransport() {
        return rwTransport;
    }

    HttpServletStreamableServerTransportProvider roTransport() {
        return roTransport;
    }

    private static McpSyncServer buildServer(
            HttpServletStreamableServerTransportProvider transport,
            ApiError.AccessMode mode,
            InspectService inspect,
            EditService edit) {
        String instructions = mode == ApiError.AccessMode.READ_WRITE
                ? "Read-write Ghidra session for a single binary. Read current version with program_info or decompile; pass expected_version to apply_edits, define_type, or revert."
                : "Read-only Ghidra session for a single binary. Write operations are disabled on this endpoint.";
        List<SyncToolSpecification> specs = buildToolDefs(mode, inspect, edit).stream()
                .map(d -> SyncToolSpecification.builder().tool(d.tool()).callHandler(d.handler()).build())
                .toList();
        return McpServer.sync(transport)
                .serverInfo(SERVER_NAME, SERVER_VERSION)
                .instructions(instructions)
                .capabilities(McpSchema.ServerCapabilities.builder().tools(false).build())
                .tools(specs)
                .build();
    }

    static List<ToolDef> buildToolDefs(ApiError.AccessMode mode) {
        return buildToolDefs(mode, null, null);
    }

    static List<ToolDef> buildToolDefs(ApiError.AccessMode mode, InspectService inspect, EditService edit) {
        // HTML escaping would show agents \u003e for > and \u0027 for quotes, in errors and in pseudocode.
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        McpSchema.ToolAnnotations readAnn = McpSchema.ToolAnnotations.builder()
                .readOnlyHint(true)
                .destructiveHint(false)
                .idempotentHint(true)
                .openWorldHint(false)
                .build();
        McpSchema.ToolAnnotations writeAnn = McpSchema.ToolAnnotations.builder()
                .readOnlyHint(false)
                .destructiveHint(false)
                .idempotentHint(false)
                .openWorldHint(false)
                .build();
        McpSchema.ToolAnnotations saveAnn = McpSchema.ToolAnnotations.builder()
                .readOnlyHint(false)
                .destructiveHint(false)
                .idempotentHint(true)
                .openWorldHint(false)
                .build();

        List<ToolDef> defs = new ArrayList<>();

        defs.add(def("program_info",
                "Return loaded binary metadata (SHA-256, arch, compiler, memory segments, function/type counts, current_version).",
                schema(List.of(), Map.of()), readAnn, gson,
                (ex, args) -> inspect.programInfo()));

        defs.add(def("list_functions",
                "List analyzed functions with addresses, sizes, and signatures without decompiling.",
                schema(List.of(), Map.of(
                        "filter", strProp("Optional case-insensitive substring matching function name or address."),
                        "sort", enumProp("Sort order: address (default), name, or size.", "address", "name", "size"),
                        "cursor", strProp("Pagination cursor from a previous list_functions call."),
                        "limit", intProp("Page size (1..200, default 50)."))),
                readAnn, gson, (ex, args) -> inspect.listFunctions(args)));

        defs.add(def("list_symbols",
                "List imports, exports, globals, defined strings, classes, or namespaces in paginated form.",
                schema(List.of("kind"), Map.of(
                        "kind", enumProp("Symbol category to list.", "imports", "exports", "globals", "strings", "classes", "namespaces"),
                        "filter", strProp("Optional case-insensitive substring matching symbol name, string text, or address."),
                        "cursor", strProp("Pagination cursor from a previous list_symbols call."),
                        "limit", intProp("Page size (1..200, default 50)."))),
                readAnn, gson, (ex, args) -> inspect.listSymbols(args)));

        defs.add(def("decompile",
                "Decompile one function to C pseudocode plus local/parameter variables (including decompiler HighSymbols) and referenced globals.",
                schema(List.of("target"), Map.of(
                        "target", strProp("Function entry address (e.g. '0x40116d' or '0040116d') or exact function name."),
                        "include_vars", boolProp("Include local variables, parameters, and referenced globals (default true)."),
                        "offset", intProp("Character offset into pseudocode for large functions (default 0)."))),
                readAnn, gson, (ex, args) -> inspect.decompile(args)));

        defs.add(def("disassemble",
                "Read bounded disassembly instructions for a function or starting at an address.",
                schema(List.of("target"), Map.of(
                        "target", strProp("Function name/address or instruction address."),
                        "max_instructions", intProp("Maximum instructions per page (1..400, default 100)."),
                        "cursor", strProp("Pagination cursor from a previous disassemble call."))),
                readAnn, gson, (ex, args) -> inspect.disassemble(args)));

        defs.add(def("get_xrefs",
                "List callers, callees, or cross-references to/from a function or address without decompiling.",
                schema(List.of("target"), Map.of(
                        "target", strProp("Function name/address or target address."),
                        "kind", enumProp("Reference filter: callers, callees, to, from, or all (default all).",
                                "callers", "callees", "to", "from", "all"),
                        "cursor", strProp("Pagination cursor from a previous get_xrefs call."),
                        "limit", intProp("Page size (1..200, default 50)."))),
                readAnn, gson, (ex, args) -> inspect.getXrefs(args)));

        defs.add(def("read_memory",
                "Read raw bytes from program memory (up to 4096 bytes) as hex, UTF-8, u32, or u64 values.",
                schema(List.of("address"), Map.of(
                        "address", strProp("Start address to read (e.g. '0x404020')."),
                        "size", intProp("Number of bytes to read (1..4096, default 64)."),
                        "format", enumProp("Output interpretation: hex (default), utf8, u32, or u64.", "hex", "utf8", "u32", "u64"))),
                readAnn, gson, (ex, args) -> inspect.readMemory(args)));

        defs.add(def("search_code",
                "Search across decompiled pseudocode, disassembly instructions, or raw byte patterns (with optional ?? wildcards).",
                schema(List.of("query", "scope"), Map.of(
                        "query", strProp("Search text for pseudocode/disassembly, or hex bytes like '55 48 ?? e5' for bytes."),
                        "scope", enumProp("Search target: pseudocode, disassembly, or bytes.", "pseudocode", "disassembly", "bytes"),
                        "cursor", strProp("Pagination cursor from a previous search_code call."),
                        "limit", intProp("Max matches per page (1..50, default 20)."))),
                readAnn, gson, (ex, args) -> inspect.searchCode(args)));

        defs.add(def("get_type",
                "Inspect data types (structs, unions, enums, typedefs, pointers) including field offsets and sizes.",
                schema(List.of("query"), Map.of(
                        "query", strProp("Type name or category path substring (or exact name when exact=true)."),
                        "exact", boolProp("Require exact name or path match (default false)."),
                        "cursor", strProp("Pagination cursor from a previous get_type call."),
                        "limit", intProp("Page size (1..50, default 20)."))),
                readAnn, gson, (ex, args) -> inspect.getType(args)));

        if (mode == ApiError.AccessMode.READ_WRITE) {
            defs.add(def("apply_edits",
                    "Apply 1..50 atomic edits in one transaction, record a new version, redecompile touched functions once, and return unified diffs. "
                            + "var_name is the name decompile showed before this batch, or a name this batch assigned. "
                            + "One failed edit rolls back all of them; the error gives its 0-based edit_index. "
                            + "Function-pointer types need a typedef from define_type first.",
                    schema(List.of("expected_version", "edits"), Map.of(
                            "expected_version", intProp("Optimistic lock version expected before these edits (from program_info or prior edit)."),
                            "reason", strProp("Short human-readable explanation recorded in version history."),
                            "edits", Map.of(
                                    "type", "array",
                                    "minItems", 1,
                                    "maxItems", 50,
                                    "description", "Ordered list of edits. Ops: "
                                            + "create_function{op,target,name?}, "
                                            + "rename_function{op,target,new_name}, "
                                            + "rename_var{op,function,var_name,new_name}, "
                                            + "set_var_type{op,function,var_name,type}, "
                                            + "rename_global{op,target,new_name,function?}, "
                                            + "set_global_type{op,target,type,allow_resize?,function?}, "
                                            + "set_signature{op,target,signature,calling_convention?}, "
                                            + "set_comment{op,target,comment_type?(function|plate|pre|eol|var),var_name?,text}.",
                                    "items", Map.of("type", "object")))),
                    writeAnn, gson, (ex, args) -> edit.applyEdits(mode, actorName(ex), args)));

            defs.add(def("define_type",
                    "Parse a C struct/union/enum/typedef declaration into the program data type manager and record a new version.",
                    schema(List.of("c_declaration", "expected_version"), Map.of(
                            "c_declaration", strProp("Valid C type declaration(s), e.g. 'typedef struct { uint32_t a; uint32_t b; } State;'."),
                            "category", strProp("Target Ghidra DataType category path (default '/mcp')."),
                            "expected_version", intProp("Optimistic lock version expected before defining this type."),
                            "reason", strProp("Short explanation recorded in version history."))),
                    writeAnn, gson, (ex, args) -> edit.defineType(mode, actorName(ex), args)));

            defs.add(def("revert",
                    "Revert committed changes back to an earlier version using stored inverse operations, creating a new linear revert version.",
                    schema(List.of("to_version", "expected_version"), Map.of(
                            "to_version", intProp("Target version >= 0 and < current version to revert back to."),
                            "expected_version", intProp("Current version expected before applying this revert."),
                            "reason", strProp("Optional explanation recorded in version history."))),
                    writeAnn, gson, (ex, args) -> edit.revert(mode, actorName(ex), args)));

            defs.add(def("save_checkpoint",
                    "Label the current saved version with an optional checkpoint name.",
                    schema(List.of(), Map.of(
                            "label", strProp("Optional checkpoint label shown in version history and WebUI."))),
                    saveAnn, gson, (ex, args) -> edit.saveCheckpoint(mode, actorName(ex), args)));
        }

        return defs;
    }

    @FunctionalInterface
    private interface HandlerWork {
        Map<String, Object> call(McpSyncServerExchange exchange, Map<String, Object> args) throws Exception;
    }

    private static ToolDef def(
            String name,
            String description,
            Map<String, Object> schema,
            McpSchema.ToolAnnotations annotations,
            Gson gson,
            HandlerWork work) {
        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name(name)
                .description(description)
                .inputSchema(schema)
                .annotations(annotations)
                .build();
        BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> handler =
                (exchange, request) -> {
                    try {
                        Map<String, Object> args = request.arguments() == null ? Map.of() : request.arguments();
                        Map<String, Object> res = work.call(exchange, args);
                        return McpSchema.CallToolResult.builder()
                                .addTextContent(gson.toJson(res))
                                .build();
                    } catch (ApiError err) {
                        Map<String, Object> detail = new LinkedHashMap<>();
                        detail.put("code", err.code);
                        detail.put("message", err.agentMessage());
                        if (err.currentVersion != null) detail.put("current_version", err.currentVersion);
                        detail.putAll(err.details);
                        return McpSchema.CallToolResult.builder()
                                .addTextContent(gson.toJson(Map.of("ok", false, "error", detail)))
                                .isError(true)
                                .build();
                    } catch (Exception ex) {
                        String msg = "Unexpected server error in " + name + ": " + ex.getClass().getSimpleName()
                                + (ex.getMessage() == null ? "" : ": " + ex.getMessage());
                        return McpSchema.CallToolResult.builder()
                                .addTextContent(gson.toJson(Map.of("ok", false, "error",
                                        Map.of("code", "OPERATION_FAILED", "message", msg))))
                                .isError(true)
                                .build();
                    }
                };
        return new ToolDef(tool, handler);
    }

    private static String actorName(McpSyncServerExchange exchange) {
        if (exchange != null && exchange.getClientInfo() != null && exchange.getClientInfo().name() != null) {
            return exchange.getClientInfo().name();
        }
        return "mcp-rw";
    }

    private static Map<String, Object> schema(List<String> required, Map<String, Object> properties) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", "object");
        m.put("properties", properties);
        m.put("required", required);
        m.put("additionalProperties", false);
        return m;
    }

    private static Map<String, Object> strProp(String description) {
        return Map.of("type", "string", "description", description);
    }

    private static Map<String, Object> intProp(String description) {
        return Map.of("type", "integer", "description", description);
    }

    private static Map<String, Object> boolProp(String description) {
        return Map.of("type", "boolean", "description", description);
    }

    private static Map<String, Object> enumProp(String description, String... values) {
        return Map.of("type", "string", "description", description, "enum", List.of(values));
    }

    @Override
    public void close() {
        try { rwServer.closeGracefully(); } catch (Exception ignored) {}
        try { roServer.closeGracefully(); } catch (Exception ignored) {}
        try { rwTransport.closeGracefully().block(Duration.ofSeconds(2)); } catch (Exception ignored) {}
        try { roTransport.closeGracefully().block(Duration.ofSeconds(2)); } catch (Exception ignored) {}
    }
}
