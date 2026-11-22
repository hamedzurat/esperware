package org.esperware.ghidramcp;

import static org.junit.jupiter.api.Assertions.*;

import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class McpAccessControlTest {
    private static final Set<String> READ_TOOLS = Set.of(
            "program_info", "list_functions", "list_symbols", "decompile",
            "disassemble", "get_xrefs", "read_memory", "search_code", "get_type");

    private static final Set<String> WRITE_TOOLS = Set.of(
            "apply_edits", "define_type", "revert", "save_checkpoint");

    @Test
    void readOnlySpecsExcludeWritesAndMarkAllReadToolsWithAnnotationsAndDescriptions() {
        List<McpSchema.Tool> roTools = McpEndpoints.buildToolDefs(ApiError.AccessMode.READ_ONLY)
                .stream().map(McpEndpoints.ToolDef::tool).toList();
        assertEquals(READ_TOOLS, roTools.stream().map(McpSchema.Tool::name).collect(Collectors.toSet()));
        for (McpSchema.Tool t : roTools) {
            assertNotNull(t.annotations(), "missing annotations on " + t.name());
            assertEquals(Boolean.TRUE, t.annotations().readOnlyHint(), "readOnlyHint must be true on " + t.name());
            assertDescriptionsPresent(t);
        }

        List<McpSchema.Tool> rwTools = McpEndpoints.buildToolDefs(ApiError.AccessMode.READ_WRITE)
                .stream().map(McpEndpoints.ToolDef::tool).toList();
        Set<String> expectedAll = new java.util.HashSet<>(READ_TOOLS);
        expectedAll.addAll(WRITE_TOOLS);
        assertEquals(expectedAll, rwTools.stream().map(McpSchema.Tool::name).collect(Collectors.toSet()));
        for (McpSchema.Tool t : rwTools) {
            assertNotNull(t.annotations(), "missing annotations on " + t.name());
            assertEquals(READ_TOOLS.contains(t.name()), Boolean.TRUE.equals(t.annotations().readOnlyHint()),
                    "readOnlyHint mismatch on " + t.name());
            assertDescriptionsPresent(t);
        }
    }

    @Test
    void editServiceBlocksReadOnlyModeBeforeTouchingProgram() {
        EditService edits = new EditService(null, null);
        ApiError err1 = assertThrows(ApiError.class, () ->
                edits.applyEdits(ApiError.AccessMode.READ_ONLY, "subagent", Map.of("expected_version", 0, "edits", List.of(Map.of("op", "rename_function")))));
        assertEquals("READ_ONLY", err1.code);

        ApiError err2 = assertThrows(ApiError.class, () ->
                edits.defineType(ApiError.AccessMode.READ_ONLY, "subagent", Map.of("expected_version", 0, "c_declaration", "struct A { int x; };")));
        assertEquals("READ_ONLY", err2.code);

        ApiError err3 = assertThrows(ApiError.class, () ->
                edits.revert(ApiError.AccessMode.READ_ONLY, "subagent", Map.of("expected_version", 1, "to_version", 0)));
        assertEquals("READ_ONLY", err3.code);

        ApiError err4 = assertThrows(ApiError.class, () ->
                edits.saveCheckpoint(ApiError.AccessMode.READ_ONLY, "subagent", Map.of()));
        assertEquals("READ_ONLY", err4.code);
    }

    @Test
    void loopbackOriginMatcherAcceptsOnlyLocalHttpOrigins() {
        assertTrue(WebApiServlet.isLoopbackOrigin("http://localhost:5173"));
        assertTrue(WebApiServlet.isLoopbackOrigin("http://127.0.0.1:4173"));
        assertTrue(WebApiServlet.isLoopbackOrigin("http://[::1]:3000"));
        assertTrue(WebApiServlet.isLoopbackOrigin("https://localhost"));

        assertFalse(WebApiServlet.isLoopbackOrigin("https://evil.com"));
        assertFalse(WebApiServlet.isLoopbackOrigin("http://localhost.evil.com:5173"));
        assertFalse(WebApiServlet.isLoopbackOrigin("null"));
        assertFalse(WebApiServlet.isLoopbackOrigin("ftp://localhost:5173"));
        assertFalse(WebApiServlet.isLoopbackOrigin("http://localhost:5173/path"));
        assertFalse(WebApiServlet.isLoopbackOrigin("http://user@localhost:5173"));
        assertFalse(WebApiServlet.isLoopbackOrigin("http://localhost:0"));
        assertFalse(WebApiServlet.isLoopbackOrigin("http://localhost:70000"));
    }

    @Test
    void servletAndApiValidationHandlePlusNamesIntBoundsAndEmptyDiffs() {
        assertEquals("operator+", WebApiServlet.decodePathSegment("operator+"));
        assertEquals("operator+ foo", WebApiServlet.decodePathSegment("operator+%20foo"));
        assertEquals("ns::operator+", WebApiServlet.decodePathSegment("ns%3A%3Aoperator%2B"));

        assertThrows(ApiError.class, () -> ApiError.optInt(Map.of("limit", 1.5), "limit", 50, 1, 200));
        assertThrows(ApiError.class, () -> ApiError.optInt(Map.of("limit", 4_294_967_346L), "limit", 50, 1, 200));
        assertThrows(ApiError.class, () -> ApiError.reqLong(Map.of("expected_version", 2.5), "expected_version", 0L));
        assertEquals(50, ApiError.optInt(Map.of("limit", 50.0), "limit", 10, 1, 200));

        String createdDiff = ApiError.unifiedDiff("created @ 00401000", "", "int main(void) {\n  return 0;\n}\n");
        assertTrue(createdDiff.contains("@@ -0,0 +1,3 @@"), createdDiff);
    }

    @SuppressWarnings("unchecked")
    private static void assertDescriptionsPresent(McpSchema.Tool t) {
        assertNotNull(t.description());
        assertFalse(t.description().isBlank(), "blank tool description on " + t.name());
        if (t.inputSchema() == null) return;
        Map<String, Object> props = (Map<String, Object>) t.inputSchema().get("properties");
        if (props == null) return;
        for (Map.Entry<String, Object> e : props.entrySet()) {
            assertInstanceOf(Map.class, e.getValue(), "property " + e.getKey() + " on " + t.name());
            Map<String, Object> prop = (Map<String, Object>) e.getValue();
            Object desc = prop.get("description");
            assertInstanceOf(String.class, desc, "missing description on " + t.name() + "." + e.getKey());
            assertFalse(((String) desc).isBlank(), "blank description on " + t.name() + "." + e.getKey());
        }
    }
}
