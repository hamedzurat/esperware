package org.esperware.ghidramcp;

import static org.junit.jupiter.api.Assertions.*;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("e2e")
class HeadlessServerE2ETest {
    private static final Set<String> READ_TOOLS = Set.of(
            "program_info", "list_functions", "list_symbols", "decompile",
            "disassemble", "get_xrefs", "read_memory", "search_code", "get_type");
    private static final Set<String> WRITE_TOOLS = Set.of(
            "apply_edits", "define_type", "revert", "save_checkpoint");

    private static final Gson GSON = new Gson();
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private static final String MODE = System.getProperty("e2e.mode", "docker");
    private static final String ENGINE = System.getProperty("e2e.engine", "podman");
    private static final String IMAGE = System.getProperty("e2e.image", "ghidra-mcp:local");

    private static Path repoDir;
    private static Path tmpRoot;
    private static Path fixturePath;
    private static final List<RunningServer> STARTED = new ArrayList<>();

    @BeforeAll
    static void setupFixture() throws Exception {
        repoDir = Path.of("").toAbsolutePath().normalize();
        Path artifactsDir = repoDir.getParent().resolve("artifacts");
        Process build = new ProcessBuilder("just", "build")
                .directory(artifactsDir.toFile())
                .inheritIO()
                .start();
        assertEquals(0, build.waitFor(), "just build in artifacts/ failed");
        fixturePath = artifactsDir.resolve("build/readability-fixture.stripped.elf");

        String sysTmp = System.getProperty("java.io.tmpdir", "/tmp");
        boolean hasDot = false;
        for (Path part : Path.of(sysTmp).toAbsolutePath().normalize()) {
            if (part.getFileName().toString().startsWith(".")) hasDot = true;
        }
        Path tmpBase = hasDot ? Path.of("/tmp") : Path.of(sysTmp);
        tmpRoot = Files.createTempDirectory(tmpBase, "ghidra-mcp-java-e2e-");
        Files.createDirectories(tmpRoot.resolve("cache"));
        Files.createDirectories(tmpRoot.resolve("input"));
        Files.copy(fixturePath, tmpRoot.resolve("input/readability-fixture.elf"));
        Files.copy(artifactsDir.resolve("build/readability-fixture.unstripped.elf"),
                tmpRoot.resolve("input/other-fixture.elf"));
    }

    @AfterAll
    static void cleanup() {
        for (RunningServer s : STARTED) s.forceStop();
        if (tmpRoot != null) {
            try (var walk = Files.walk(tmpRoot)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (Exception ignored) {}
                });
            } catch (Exception ignored) {}
        }
    }

    @Test
    void fullHeadlessLifecycleRoRwVersionsWebUiAndCache() throws Exception {
        RunningServer srv1 = startServer("run-1", true, "--cors-origin", "null");
        String baseUrl = srv1.baseUrl;
        String apiUrl = baseUrl + "/api/v1";

        // 1. Read-only subagent on /mcp/ro
        StreamableMcpClient ro = new StreamableMcpClient(baseUrl + "/mcp/ro", "subagent-ro");
        JsonArray roTools = ro.listTools();
        Set<String> roNames = new HashSet<>();
        for (JsonElement el : roTools) {
            JsonObject t = el.getAsJsonObject();
            roNames.add(t.get("name").getAsString());
            assertTrue(t.getAsJsonObject("annotations").get("readOnlyHint").getAsBoolean(),
                    "readOnlyHint missing on " + t.get("name"));
        }
        assertEquals(READ_TOOLS, roNames);

        JsonObject info = ro.callOk("program_info", Map.of());
        assertEquals(0L, info.get("version").getAsLong());
        assertTrue(info.get("function_count").getAsInt() > 2);

        JsonObject fnList = ro.callOk("list_functions", Map.of("limit", 100));
        assertTrue(fnList.getAsJsonArray("functions").size() > 2);

        assertTrue(ro.callOk("list_symbols", Map.of("kind", "imports")).get("ok").getAsBoolean());
        assertTrue(ro.callOk("list_symbols", Map.of("kind", "strings")).get("ok").getAsBoolean());
        assertTrue(ro.callOk("list_symbols", Map.of("kind", "globals")).get("ok").getAsBoolean());
        var imports = ro.callOk("list_symbols", Map.of("kind", "imports", "limit", 1));
        String importCursor = imports.get("next_cursor").getAsString();
        var filteredImports = ro.callOk("list_symbols", Map.of("kind", "imports", "cursor", importCursor,
                "filter", "no_matching_import_in_the_fixture"));
        assertTrue(filteredImports.getAsJsonArray("items").isEmpty());
        assertFalse(filteredImports.has("next_cursor"));

        // Find mix() via 0x7feb352d constant in pseudocode, then caller transform()
        JsonObject searchPseudo = ro.callOk("search_code", Map.of("query", "7feb352d", "scope", "pseudocode"));
        JsonArray pseudoMatches = searchPseudo.getAsJsonArray("matches");
        assertTrue(pseudoMatches.size() > 0, "Expected 7feb352d match");
        String mixAddr = pseudoMatches.get(0).getAsJsonObject().get("address").getAsString();

        JsonObject xrefs = ro.callOk("get_xrefs", Map.of("target", mixAddr, "kind", "callers"));
        String transformAddr = null;
        for (JsonElement el : xrefs.getAsJsonArray("xrefs")) {
            JsonObject x = el.getAsJsonObject();
            if ("caller".equals(x.get("kind").getAsString())) {
                transformAddr = x.get("address").getAsString();
                break;
            }
        }
        assertNotNull(transformAddr, "Expected caller for mix");
        String endCursor = ApiError.encodeCursor(GSON, Map.of("offset", Integer.MAX_VALUE));
        assertTrue(ro.callOk("get_xrefs", Map.of("target", mixAddr, "cursor", endCursor))
                .getAsJsonArray("xrefs").isEmpty());

        JsonObject dec = ro.callOk("decompile", Map.of("target", transformAddr));
        assertEquals("complete", dec.get("decompile_status").getAsString());
        String localVar = null;
        for (JsonElement el : dec.getAsJsonArray("variables")) {
            JsonObject v = el.getAsJsonObject();
            if ("local".equals(v.get("kind").getAsString())) {
                localVar = v.get("name").getAsString();
                break;
            }
        }
        assertNotNull(localVar, "Expected local variable in transform");
        JsonArray refGlobals = dec.getAsJsonArray("globals");
        assertTrue(refGlobals.size() >= 2, "Expected >=2 referenced globals in transform");
        String g0Addr = refGlobals.get(0).getAsJsonObject().get("address").getAsString();
        String g1Addr = refGlobals.get(1).getAsJsonObject().get("address").getAsString();

        JsonObject dis = ro.callOk("disassemble", Map.of("target", transformAddr, "max_instructions", 10));
        JsonArray insns = dis.getAsJsonArray("instructions");
        assertTrue(insns.size() > 0);
        StringBuilder pat = new StringBuilder();
        for (int i = 0; i < Math.min(2, insns.size()); i++) {
            pat.append(insns.get(i).getAsJsonObject().get("bytes").getAsString());
        }
        String firstBytes = pat.substring(0, Math.min(6, pat.length()));

        // Locate main() address passed in RDI by entry -> __libc_start_main
        JsonObject entryDis = ro.callOk("disassemble", Map.of("target", "entry", "max_instructions", 30));
        String mainAddr = null;
        for (JsonElement el : entryDis.getAsJsonArray("instructions")) {
            JsonObject ins = el.getAsJsonObject();
            String mn = ins.get("mnemonic").getAsString();
            String ops = ins.get("operands").getAsString();
            if ("MOV".equals(mn) && ops.startsWith("RDI,0x")) {
                mainAddr = ops.substring("RDI,".length()).trim();
                break;
            }
        }
        assertNotNull(mainAddr, "Expected MOV RDI,0x... in entry disassembly");
        assertTrue(ro.callRaw("decompile", Map.of("target", mainAddr)).isError(),
                "Expected main before create_function to be unrecovered");

        JsonObject mem = ro.callOk("read_memory", Map.of("address", transformAddr, "size", 16, "format", "hex"));
        assertEquals(16, mem.get("size").getAsInt());

        JsonObject searchBytes = ro.callOk("search_code", Map.of("query", firstBytes, "scope", "bytes", "limit", 5));
        assertTrue(searchBytes.getAsJsonArray("matches").size() > 0);

        JsonObject builtinType = ro.callOk("get_type", Map.of("query", "uint", "exact", true));
        assertTrue(builtinType.getAsJsonArray("types").size() > 0);

        // /mcp/ro must reject writes
        assertTrue(ro.callRaw("apply_edits", Map.of("expected_version", 0, "edits", List.of())).isError());

        // 2. Read-write agent on /mcp/rw
        StreamableMcpClient rw = new StreamableMcpClient(baseUrl + "/mcp/rw", "main-rw");
        Set<String> rwNames = new HashSet<>();
        for (JsonElement el : rw.listTools()) rwNames.add(el.getAsJsonObject().get("name").getAsString());
        Set<String> expectedAll = new HashSet<>(READ_TOOLS);
        expectedAll.addAll(WRITE_TOOLS);
        assertEquals(expectedAll, rwNames);

        JsonObject defType = rw.callOk("define_type", Map.of(
                "c_declaration", "struct ProbeState { unsigned int value; unsigned int salt; };",
                "category", "/probe",
                "expected_version", 0,
                "reason", "define ProbeState struct"));
        assertEquals(1L, defType.get("version").getAsLong());

        JsonObject customTypes = ro.callOk("get_type", Map.of("query", "ProbeState"));
        assertTrue(customTypes.getAsJsonArray("types").size() > 0);

        // Intra-batch rename_function -> reference by NEW name ("transform_fn") in rename_global
        JsonObject batch = rw.callOk("apply_edits", Map.of(
                "expected_version", 1,
                "reason", "clean up transform",
                "edits", List.of(
                        Map.of("op", "rename_function", "target", transformAddr, "new_name", "transform_fn"),
                        Map.of("op", "rename_var", "function", "transform_fn", "var_name", localVar, "new_name", "mixed_state"),
                        Map.of("op", "rename_global", "target", g0Addr, "new_name", "g_probe_state", "function", "transform_fn"),
                        Map.of("op", "set_comment", "target", transformAddr, "comment_type", "function", "text", "Transforms input via mix()"),
                        Map.of("op", "set_comment", "target", transformAddr, "comment_type", "pre", "text", "Entry pre-comment"))));
        assertEquals(2L, batch.get("version").getAsLong());
        String stepDiff = batch.getAsJsonArray("diffs").get(0).getAsJsonObject().get("diff").getAsString();
        assertTrue(stepDiff.contains("transform_fn"));
        assertTrue(stepDiff.contains("mixed_state"));
        assertTrue(stepDiff.contains("g_probe_state"));

        // Failed partial batch must roll back cleanly AND must NOT poison subsequent save_checkpoint
        var failedBatch = rw.callRaw("apply_edits", Map.of(
                "expected_version", 2,
                "reason", "should roll back",
                "edits", List.of(
                        Map.of("op", "rename_var", "function", "transform_fn", "var_name", "mixed_state", "new_name", "leaked_var"),
                        Map.of("op", "rename_var", "function", "transform_fn", "var_name", "nonexistent_var_xyz", "new_name", "nope"))));
        assertTrue(failedBatch.isError());
        assertEquals("VARIABLE_NOT_FOUND", failedBatch.body().getAsJsonObject("error").get("code").getAsString());
        JsonObject afterFailedDec = rw.callOk("decompile", Map.of("target", transformAddr));
        assertFalse(afterFailedDec.get("pseudocode").getAsString().contains("leaked_var"),
                "Failed batch leaked var rename");
        assertTrue(afterFailedDec.get("pseudocode").getAsString().contains("mixed_state"));

        JsonObject chk = rw.callOk("save_checkpoint", Map.of("label", "after-transform"));
        assertEquals(2L, chk.get("version").getAsLong());
        JsonObject afterChkDec = rw.callOk("decompile", Map.of("target", transformAddr));
        assertEquals("transform_fn", afterChkDec.getAsJsonObject("function").get("name").getAsString());
        assertTrue(afterChkDec.get("pseudocode").getAsString().contains("mixed_state"),
                "save_checkpoint after failed batch lost committed edits");

        // set_signature should not trigger Unknown calling convention warning
        JsonObject sigBatch = rw.callOk("apply_edits", Map.of(
                "expected_version", 2,
                "reason", "set transform signature",
                "edits", List.of(
                        Map.of("op", "set_signature", "target", "transform_fn",
                                "signature", "uint32_t transform_fn(uint32_t a, uint32_t b)"))));
        assertEquals(3L, sigBatch.get("version").getAsLong());
        String sigDiff = sigBatch.getAsJsonArray("diffs").get(0).getAsJsonObject().get("diff").getAsString();
        assertFalse(sigDiff.contains("Unknown calling convention"), "Unexpected warning in diff:\n" + sigDiff);
        assertTrue(sigDiff.contains("uint32_t transform_fn("));

        // Bare short type name ("ProbeState") rejected without allow_resize, accepted with allow_resize=true
        var unsafeGlobal = rw.callRaw("apply_edits", Map.of(
                "expected_version", 3,
                "edits", List.of(Map.of("op", "set_global_type", "target", g0Addr, "type", "ProbeState"))));
        assertTrue(unsafeGlobal.isError());
        assertEquals("UNSAFE_GLOBAL_TYPE", unsafeGlobal.body().getAsJsonObject("error").get("code").getAsString());

        JsonObject overlayBatch = rw.callOk("apply_edits", Map.of(
                "expected_version", 3,
                "reason", "overlay 8-byte ProbeState across adjacent globals",
                "edits", List.of(Map.of(
                        "op", "set_global_type",
                        "target", g0Addr,
                        "type", "ProbeState",
                        "allow_resize", true))));
        assertEquals(4L, overlayBatch.get("version").getAsLong());
        JsonObject afterOverlayDec = rw.callOk("decompile", Map.of("target", transformAddr));
        assertTrue(afterOverlayDec.getAsJsonArray("globals").toString().contains("ProbeState"),
                "Expected ProbeState in transform globals: " + afterOverlayDec.getAsJsonArray("globals"));

        // create_function + intra-batch set_signature on unrecovered main
        JsonObject mainBatch = rw.callOk("apply_edits", Map.of(
                "expected_version", 4,
                "reason", "create and type recovered_main",
                "edits", List.of(
                        Map.of("op", "create_function", "target", mainAddr, "name", "recovered_main"),
                        Map.of("op", "set_signature", "target", "recovered_main",
                                "signature", "int recovered_main(int argc, char **argv)"))));
        assertEquals(5L, mainBatch.get("version").getAsLong());
        JsonObject mainDec = ro.callOk("decompile", Map.of("target", "recovered_main"));
        assertEquals("complete", mainDec.get("decompile_status").getAsString());
        assertTrue(mainDec.get("pseudocode").getAsString().contains("transform_fn"),
                "Expected recovered_main to call transform_fn:\n" + mainDec.get("pseudocode").getAsString());

        // Stale expected_version fails without advancing version
        var stale = rw.callRaw("apply_edits", Map.of(
                "expected_version", 0,
                "edits", List.of(Map.of("op", "rename_function", "target", transformAddr, "new_name", "nope"))));
        assertTrue(stale.isError());
        assertEquals("STALE_VERSION", stale.body().getAsJsonObject("error").get("code").getAsString());

        JsonObject chk2 = rw.callOk("save_checkpoint", Map.of("label", "after-main"));
        assertEquals(5L, chk2.get("version").getAsLong());

        var internal = rw.callRaw("apply_edits", Map.of("expected_version", 5, "edits",
                List.of(Map.of("op", "remove_type", "path", "/mcp/ProbeState"))));
        assertTrue(internal.isError());
        assertEquals("INVALID_ARGUMENT", internal.body().getAsJsonObject("error").get("code").getAsString());

        // 3. REST + CORS (for external wui/) + SSE checks
        HttpResponse<String> rootResp = get(baseUrl + "/");
        assertEquals(404, rootResp.statusCode());

        HttpResponse<String> statusResp = get(apiUrl + "/status");
        assertEquals(200, statusResp.statusCode());
        assertTrue(statusResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
        assertEquals(404, get(baseUrl + "/viewer").statusCode());
        var standaloneStatus = HttpRequest.newBuilder(URI.create(apiUrl + "/status")).header("Origin", "null").build();
        var standaloneResponse = HTTP.send(standaloneStatus, HttpResponse.BodyHandlers.discarding());
        assertEquals(200, standaloneResponse.statusCode());
        assertEquals("null", standaloneResponse.headers().firstValue("Access-Control-Allow-Origin").orElseThrow());

        JsonObject versions = getJson(apiUrl + "/versions");
        assertEquals(5L, versions.get("current_version").getAsLong());
        assertEquals(6, versions.getAsJsonArray("versions").size());
        JsonObject v5Summary = versions.getAsJsonArray("versions").get(5).getAsJsonObject();
        assertFalse(v5Summary.has("before_c"));
        assertEquals("after-main", v5Summary.get("checkpoint_label").getAsString());

        JsonObject cumDiff = getJson(apiUrl + "/diff?from=0&to=5");
        assertTrue(cumDiff.getAsJsonArray("diffs").toString().contains("Transforms input via mix()"));

        JsonObject fnDetail = getJson(apiUrl + "/functions/" + URLEncoder.encode(transformAddr, StandardCharsets.UTF_8));
        assertEquals("transform_fn", fnDetail.getAsJsonObject("function").get("name").getAsString());
        assertTrue(fnDetail.get("pseudocode").getAsString().contains("mixed_state"));

        // SSE status event check
        HttpRequest sseReq = HttpRequest.newBuilder(URI.create(apiUrl + "/events"))
                .timeout(Duration.ofSeconds(10)).GET().build();
        HttpResponse<InputStream> sseResp = HTTP.send(sseReq, HttpResponse.BodyHandlers.ofInputStream());
        assertEquals(200, sseResp.statusCode());
        try (BufferedReader br = new BufferedReader(new InputStreamReader(sseResp.body(), StandardCharsets.UTF_8))) {
            String l1 = br.readLine();
            String l2 = br.readLine();
            assertNotNull(l1);
            assertNotNull(l2);
            assertTrue(l1.contains("event: status"), l1);
            assertTrue(l2.contains("\"version\":5"), l2);
        }

        // 4. Graceful shutdown -> restart on same work-dir -> verify persistence -> full revert to v0
        srv1.shutdownAndAwait();
        assertFalse(Files.exists(tmpRoot.resolve("run-1/ready.json")));

        RunningServer srv2 = startServer("run-1", false);
        assertEquals(5L, srv2.readyJson.get("current_version").getAsLong());
        StreamableMcpClient rw2 = new StreamableMcpClient(srv2.baseUrl + "/mcp/rw", "main-rw-2");
        JsonObject persistedTransform = rw2.callOk("decompile", Map.of("target", transformAddr));
        assertEquals("transform_fn", persistedTransform.getAsJsonObject("function").get("name").getAsString());
        assertTrue(persistedTransform.getAsJsonArray("globals").toString().contains("ProbeState"));
        assertEquals("complete", rw2.callOk("decompile", Map.of("target", "recovered_main")).get("decompile_status").getAsString());

        JsonObject reverted = rw2.callOk("revert", Map.of(
                "to_version", 0, "expected_version", 5, "reason", "full rollback test"));
        assertEquals(6L, reverted.get("version").getAsLong());

        JsonObject afterDec = rw2.callOk("decompile", Map.of("target", transformAddr));
        assertFalse(afterDec.get("pseudocode").getAsString().contains("transform_fn"));
        assertFalse(afterDec.get("pseudocode").getAsString().contains("mixed_state"));
        assertFalse(afterDec.getAsJsonArray("globals").toString().contains("ProbeState"),
                "ProbeState global overlay was not reverted");
        Set<String> restoredGlobalAddrs = new HashSet<>();
        for (JsonElement el : afterDec.getAsJsonArray("globals")) {
            restoredGlobalAddrs.add(el.getAsJsonObject().get("address").getAsString());
        }
        assertTrue(restoredGlobalAddrs.contains(g0Addr), "Missing restored global " + g0Addr);
        assertTrue(restoredGlobalAddrs.contains(g1Addr), "Missing restored adjacent global " + g1Addr);
        assertTrue(rw2.callRaw("decompile", Map.of("target", mainAddr)).isError(),
                "recovered_main should be deleted on revert to v0");
        JsonObject afterTypes = rw2.callOk("get_type", Map.of("query", "ProbeState", "exact", true));
        assertEquals(0, afterTypes.get("total").getAsInt());
        var incomplete = rw2.callRaw("revert", Map.of("to_version", 5, "expected_version", 6));
        assertTrue(incomplete.isError());
        assertEquals("REVERT_UNAVAILABLE", incomplete.body().getAsJsonObject("error").get("code").getAsString());
        srv2.shutdownAndAwait();

        // 5. Cache hit on fresh run-2
        String sha = srv1.readyJson.get("binary_sha256").getAsString();
        assertTrue(Files.exists(tmpRoot.resolve("cache").resolve(sha).resolve("workspace.gpr")));
        RunningServer srv3 = startServer("run-2-cached", true);
        assertEquals(0L, srv3.readyJson.get("current_version").getAsLong());
        assertEquals(sha, srv3.readyJson.get("binary_sha256").getAsString());
        srv3.shutdownAndAwait();
    }

    @Test
    void accessPolicyAndAcknowledgedEditsSurviveAnAbruptExit() throws Exception {
        String[] access = {"--rw-token", "e2e-write", "--ro-token", "e2e-read",
                "--cors-origin", "http://localhost:9876"};
        RunningServer server = startServer("durability", true, access);
        AssertionError busy = assertThrows(AssertionError.class, () -> startServer("durability", false));
        assertTrue(busy.getMessage().contains("Workspace is already in use"), busy.getMessage());
        assertEquals(server.readyJson, JsonParser.parseString(Files.readString(server.readyFile)).getAsJsonObject());
        String base = server.baseUrl;
        String api = base + "/api/v1";
        assertEquals(200, get(api + "/health").statusCode());
        for (String path : List.of("/api/v1/status", "/api/v1/functions", "/api/v1/versions",
                "/api/v1/diff", "/api/v1/events", "/mcp/ro", "/mcp/rw")) {
            assertEquals(401, get(base + path).statusCode(), path);
        }

        var allowed = HttpRequest.newBuilder(URI.create(api + "/status"))
                .header("Authorization", "Bearer e2e-read")
                .header("Origin", "http://localhost:9876").build();
        var allowedResponse = HTTP.send(allowed, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, allowedResponse.statusCode());
        assertEquals("http://localhost:9876",
                allowedResponse.headers().firstValue("Access-Control-Allow-Origin").orElseThrow());
        var otherOrigin = HttpRequest.newBuilder(URI.create(api + "/status"))
                .header("Authorization", "Bearer e2e-read")
                .header("Origin", "http://localhost:9875").build();
        assertEquals(403, HTTP.send(otherOrigin, HttpResponse.BodyHandlers.discarding()).statusCode());

        for (String route : List.of("/api/v1/events", "/mcp/ro", "/mcp/rw")) {
            var preflight = HttpRequest.newBuilder(URI.create(base + route))
                    .header("Origin", "http://localhost:9876")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "Authorization, Mcp-Session-Id")
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build();
            var response = HTTP.send(preflight, HttpResponse.BodyHandlers.discarding());
            assertEquals(204, response.statusCode(), route);
            assertTrue(response.headers().firstValue("Access-Control-Allow-Headers").orElseThrow()
                    .contains("Mcp-Session-Id"), route);
        }

        var shutdown = HttpRequest.newBuilder(URI.create(api + "/shutdown"))
                .header("Authorization", "Bearer e2e-read")
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        assertEquals(401, HTTP.send(shutdown, HttpResponse.BodyHandlers.discarding()).statusCode());

        StreamableMcpClient ro = new StreamableMcpClient(base + "/mcp/ro", "secured-ro", "e2e-read");
        StreamableMcpClient rw = new StreamableMcpClient(base + "/mcp/rw", "secured-rw", "e2e-write");
        var eventRequest = HttpRequest.newBuilder(URI.create(api + "/events"))
                .timeout(Duration.ofSeconds(10)).header("Authorization", "Bearer e2e-read").build();
        var events = HTTP.send(eventRequest, HttpResponse.BodyHandlers.ofInputStream());
        assertEquals(200, events.statusCode());
        try (var reader = new BufferedReader(new InputStreamReader(events.body(), StandardCharsets.UTF_8))) {
            rw.callOk("define_type", Map.of("expected_version", 0,
                    "c_declaration", "enum AuditEnum { FIRST = 0, ALIAS = 0, LAST = 2 }; "
                            + "typedef struct AuditRecord { int value; } AuditRecordAlias;"));
            assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
                assertEquals("event: status", reader.readLine());
                assertTrue(reader.readLine().startsWith("data: "));
                assertEquals("", reader.readLine());
                assertEquals("event: version_created", reader.readLine());
            });
        }

        var duplicate = rw.callRaw("define_type", Map.of("expected_version", 1,
                "c_declaration", "enum AuditEnum { REPLACEMENT = 5 };"));
        assertTrue(duplicate.isError());
        assertEquals("TYPE_EXISTS", duplicate.body().getAsJsonObject("error").get("code").getAsString());

        String db = "jdbc:sqlite:" + tmpRoot.resolve("durability/history.sqlite");
        try (var conn = DriverManager.getConnection(db); var st = conn.createStatement()) {
            st.execute("CREATE TRIGGER fail_edit BEFORE INSERT ON versions "
                    + "BEGIN SELECT RAISE(ABORT, 'injected history failure'); END;");
            var failed = rw.callRaw("define_type", Map.of("expected_version", 1,
                    "c_declaration", "struct Unrecorded { int a; };"));
            assertTrue(failed.isError());
            assertEquals(1, ro.callOk("program_info", Map.of()).get("version").getAsInt());
            assertEquals(0, ro.callOk("get_type", Map.of("query", "Unrecorded")).get("total").getAsInt());
            st.execute("DROP TRIGGER fail_edit");
        }

        server.forceStop();
        assertTrue(server.proc.waitFor(20, TimeUnit.SECONDS), "Server did not terminate");
        String otherPath = "local".equalsIgnoreCase(MODE)
                ? tmpRoot.resolve("input/other-fixture.elf").toString() : "/data/input/other-fixture.elf";
        AssertionError mismatch = assertThrows(AssertionError.class,
                () -> startServer("durability", false, "--binary", otherPath));
        assertTrue(mismatch.getMessage().contains("Binary does not match the saved workspace"), mismatch.getMessage());

        RunningServer reopened = startServer("durability", false);
        assertEquals(1, reopened.readyJson.get("current_version").getAsInt());
        var resumed = new StreamableMcpClient(reopened.baseUrl + "/mcp/ro", "resumed");
        var types = resumed.callOk("get_type", Map.of("query", "AuditEnum", "exact", true)).getAsJsonArray("types");
        var values = types.get(0).getAsJsonObject().getAsJsonArray("values");
        Map<String, Integer> byName = new HashMap<>();
        for (var value : values) {
            var entry = value.getAsJsonObject();
            byName.put(entry.get("name").getAsString(), entry.get("value").getAsInt());
        }
        assertEquals(Map.of("FIRST", 0, "ALIAS", 0, "LAST", 2), byName);
        var typedef = resumed.callOk("get_type", Map.of("query", "/mcp/AuditRecordAlias", "exact", true))
                .getAsJsonArray("types").get(0).getAsJsonObject();
        assertEquals("typedef", typedef.get("kind").getAsString());
        assertEquals("/mcp/AuditRecord", typedef.get("base_path").getAsString());
        var records = resumed.callOk("get_type", Map.of("query", "AuditRecord", "exact", true))
                .getAsJsonArray("types");
        assertEquals(1, records.size());
        assertEquals("value", records.get(0).getAsJsonObject().getAsJsonArray("fields")
                .get(0).getAsJsonObject().get("name").getAsString());

        var resumedWriter = new StreamableMcpClient(reopened.baseUrl + "/mcp/rw", "resumed-rw");
        try (var conn = DriverManager.getConnection(db); var st = conn.createStatement()) {
            st.execute("CREATE TRIGGER fail_publication BEFORE DELETE ON meta "
                    + "WHEN OLD.key = 'pending_version' BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END;");
            var interrupted = resumedWriter.callRaw("define_type", Map.of("expected_version", 1,
                    "c_declaration", "struct SavedPending { int a; };"));
            assertTrue(interrupted.isError());
            assertEquals("RECOVERY_REQUIRED", interrupted.body().getAsJsonObject("error").get("code").getAsString());
            var health = get(reopened.baseUrl + "/api/v1/health");
            assertEquals(503, health.statusCode());
            assertEquals("recovery_required", JsonParser.parseString(health.body()).getAsJsonObject().get("status").getAsString());
            assertEquals(503, get(reopened.baseUrl + "/api/v1/status").statusCode());
            assertEquals(503, get(reopened.baseUrl + "/api/v1/versions").statusCode());
            st.execute("DROP TRIGGER fail_publication");
        }
        reopened.shutdownAndAwait();
        RunningServer recovered = startServer("durability", false);
        assertEquals(2, recovered.readyJson.get("current_version").getAsInt());
        var recoveredReader = new StreamableMcpClient(recovered.baseUrl + "/mcp/ro", "recovered-ro");
        assertEquals(1, recoveredReader.callOk("get_type", Map.of("query", "SavedPending", "exact", true))
                .get("total").getAsInt());
        recovered.shutdownAndAwait();
    }

    @Test
    void cliDumpAndApiExportProduceZeroDuplicationCodeLayout() throws Exception {
        // 1. One-shot CLI --dump on unstripped fixture
        Path dumpWork = tmpRoot.resolve("dump-unstripped");
        Files.createDirectories(dumpWork);
        List<String> dumpCmd;
        if ("local".equalsIgnoreCase(MODE)) {
            dumpCmd = List.of(
                    repoDir.resolve("bin/ghidra-mcp").toString(),
                    "--binary", tmpRoot.resolve("input/other-fixture.elf").toString(),
                    "--work-dir", dumpWork.toString(),
                    "--no-cache",
                    "--dump");
        } else {
            dumpCmd = List.of(
                    ENGINE, "run", "--rm",
                    "-v", tmpRoot + ":/data",
                    IMAGE,
                    "--binary", "/data/input/other-fixture.elf",
                    "--work-dir", "/data/dump-unstripped",
                    "--no-cache",
                    "--dump");
        }
        Process dumpProc = new ProcessBuilder(dumpCmd).directory(repoDir.toFile()).start();
        assertTrue(dumpProc.waitFor(90, TimeUnit.SECONDS), "--dump timed out");
        String dumpOut = new String(dumpProc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String dumpErr = new String(dumpProc.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, dumpProc.exitValue(), "--dump failed:\nSTDOUT:\n" + dumpOut + "\nSTDERR:\n" + dumpErr);

        String lastJsonLine = dumpOut.lines().map(String::trim).filter(s -> s.startsWith("{"))
                .reduce((first, second) -> second).orElseThrow(() -> new AssertionError("No JSON summary: " + dumpOut));
        JsonObject dumpSummary = JsonParser.parseString(lastJsonLine).getAsJsonObject();
        assertTrue(dumpSummary.get("ok").getAsBoolean());
        assertEquals(0L, dumpSummary.get("version").getAsLong());
        assertEquals("code/v0", dumpSummary.get("dir").getAsString());
        assertFalse(Files.exists(dumpWork.resolve("ready.json")));
        assertFalse(Files.exists(dumpWork.resolve("history.sqlite")));

        Path v0 = dumpWork.resolve("code/v0");
        assertTrue(Files.isRegularFile(v0.resolve("manifest.json")));
        assertTrue(Files.isRegularFile(v0.resolve("types.h")));
        assertTrue(Files.isRegularFile(v0.resolve("symbols.json")));
        assertTrue(Files.isRegularFile(v0.resolve("functions.jsonl")));
        assertTrue(Files.isRegularFile(v0.resolve("callgraph.jsonl")));
        assertFalse(Files.exists(v0.resolve("src/readability-fixture.c")));
        assertFalse(Files.exists(v0.resolve("src/_unmapped.c")));
        assertFalse(Files.exists(v0.resolve("src/_sec")));
        assertFalse(Files.exists(v0.resolve("src/_text")));
        assertTrue(Files.isRegularFile(v0.resolve("src/001129.c")));
        assertTrue(Files.isRegularFile(v0.resolve("src/001153.c")));
        assertTrue(Files.isRegularFile(v0.resolve("src/00119a.c")));
        assertFalse(Files.exists(v0.resolve("types.json")));
        assertFalse(Files.exists(v0.resolve("source_map.jsonl")));
        assertFalse(Files.exists(v0.resolve("functions")));
        try (var walk = Files.walk(v0)) {
            assertEquals(0L, walk.filter(p -> p.toString().endsWith(".asm")).count());
        }

        assertTrue(Files.readString(v0.resolve("types.h"), StandardCharsets.UTF_8).contains("ProbeState"),
                "types.h missing ProbeState");
        assertTrue(Files.readString(v0.resolve("symbols.json"), StandardCharsets.UTF_8).contains("probe_state"),
                "symbols.json missing probe_state");

        String mainSrc = Files.readString(v0.resolve("src/00119a.c"), StandardCharsets.UTF_8);
        assertTrue(mainSrc.startsWith("#include \"../types.h\"\n"), mainSrc);
        assertTrue(mainSrc.contains("int main("), mainSrc);
        assertTrue(mainSrc.contains("readability-fixture.c:26-30"), mainSrc);

        Map<String, JsonObject> fnRows = new HashMap<>();
        Set<String> exportedSourceFiles = new HashSet<>();
        for (String line : Files.readAllLines(v0.resolve("functions.jsonl"), StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            JsonObject row = JsonParser.parseString(line).getAsJsonObject();
            assertFalse(row.has("callers"));
            assertFalse(row.has("callees"));
            assertFalse(row.has("referenced_globals"));
            assertFalse(row.has("pseudocode"));
            assertNotEquals("00405000", row.get("entry_address").getAsString(),
                    "EXTERNAL stub should not be exported in functions.jsonl");
            String entryOffset = row.get("entry_offset").getAsString();
            String sourceFile = row.get("src_file").getAsString();
            assertEquals("src/" + entryOffset + ".c", sourceFile);
            assertTrue(Files.isRegularFile(v0.resolve(sourceFile)), "Missing function source " + sourceFile);
            assertTrue(exportedSourceFiles.add(sourceFile), "Duplicate function source file " + sourceFile);
            fnRows.put(row.get("name").getAsString(), row);
        }
        assertFalse(fnRows.containsKey("__libc_start_main"),
                "EXTERNAL stub should not be exported in functions.jsonl");
        assertEquals(fnRows.size(), exportedSourceFiles.size());
        for (String expectedFn : List.of("mix", "transform", "main")) {
            JsonObject row = fnRows.get(expectedFn);
            assertNotNull(row, "Missing function in functions.jsonl: " + expectedFn);
            String expectedOffset = switch (expectedFn) {
                case "mix" -> "001129";
                case "transform" -> "001153";
                case "main" -> "00119a";
                default -> throw new AssertionError(expectedFn);
            };
            assertEquals(expectedOffset, row.get("entry_offset").getAsString());
            assertEquals("src/" + expectedOffset + ".c", row.get("src_file").getAsString());
            assertEquals("complete", row.get("decompile_status").getAsString());
            assertTrue(row.getAsJsonArray("variables").size() > 0, "Expected variables for " + expectedFn);
            assertTrue(row.getAsJsonArray("lines").size() > 0, "Expected DWARF lines for " + expectedFn);
        }

        boolean sawCallEdge = false;
        boolean sawDataEdge = false;
        for (String line : Files.readAllLines(v0.resolve("callgraph.jsonl"), StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            JsonObject edge = JsonParser.parseString(line).getAsJsonObject();
            if ("transform".equals(edge.get("from_fn").getAsString())) {
                String kind = edge.get("kind").getAsString();
                String toName = edge.get("to_name").getAsString();
                if ("call".equals(kind) && "mix".equals(toName)) sawCallEdge = true;
                if ("data".equals(kind) && "probe_state".equals(toName)) sawDataEdge = true;
            }
        }
        assertTrue(sawCallEdge, "Expected transform -> mix call edge in callgraph.jsonl");
        assertTrue(sawDataEdge, "Expected transform -> probe_state data edge in callgraph.jsonl");

        JsonObject manifest = JsonParser.parseString(Files.readString(v0.resolve("manifest.json"), StandardCharsets.UTF_8))
                .getAsJsonObject();
        assertEquals(0L, manifest.get("version").getAsLong());
        assertTrue(manifest.getAsJsonObject("counts").get("functions").getAsInt() >= 3);

        // 2. Live server: does not auto-export; POST /api/v1/export requires rw token and tracks versions
        RunningServer server = startServer("api-export", true, "--rw-token", "exp-rw", "--ro-token", "exp-ro");
        assertFalse(Files.exists(tmpRoot.resolve("api-export/code")),
                "Server must not export automatically on startup");

        String exportUrl = server.baseUrl + "/api/v1/export";
        assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(exportUrl))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding()).statusCode());
        assertEquals(401, HTTP.send(HttpRequest.newBuilder(URI.create(exportUrl))
                .header("Authorization", "Bearer exp-ro")
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding()).statusCode());

        HttpResponse<String> expV0Resp = HTTP.send(HttpRequest.newBuilder(URI.create(exportUrl))
                .header("Authorization", "Bearer exp-rw")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, expV0Resp.statusCode(), expV0Resp.body());
        JsonObject expV0 = JsonParser.parseString(expV0Resp.body()).getAsJsonObject();
        assertEquals(0L, expV0.get("version").getAsLong());
        assertEquals("code/v0", expV0.get("dir").getAsString());
        assertFalse(expV0.has("path"));
        Path manifestPath = tmpRoot.resolve("api-export/code/v0/manifest.json");
        assertTrue(Files.isRegularFile(manifestPath));
        Files.setLastModifiedTime(manifestPath, java.nio.file.attribute.FileTime.fromMillis(1_000_000));
        var publishedAt = Files.getLastModifiedTime(manifestPath);

        HttpResponse<String> repeatedExport = HTTP.send(HttpRequest.newBuilder(URI.create(exportUrl))
                .header("Authorization", "Bearer exp-rw")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, repeatedExport.statusCode(), repeatedExport.body());
        assertEquals(expV0, JsonParser.parseString(repeatedExport.body()).getAsJsonObject());
        assertEquals(publishedAt, Files.getLastModifiedTime(manifestPath));

        JsonObject legacyManifest = JsonParser.parseString(Files.readString(manifestPath, StandardCharsets.UTF_8))
                .getAsJsonObject();
        legacyManifest.remove("export_layout_version");
        Files.writeString(manifestPath, legacyManifest.toString(), StandardCharsets.UTF_8);
        HttpResponse<String> refreshedExport = HTTP.send(HttpRequest.newBuilder(URI.create(exportUrl))
                .header("Authorization", "Bearer exp-rw")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, refreshedExport.statusCode(), refreshedExport.body());
        JsonObject refreshedManifest = JsonParser.parseString(Files.readString(manifestPath, StandardCharsets.UTF_8))
                .getAsJsonObject();
        assertEquals(2, refreshedManifest.get("export_layout_version").getAsInt());
        publishedAt = Files.getLastModifiedTime(manifestPath);

        Path typesPath = manifestPath.resolveSibling("types.h");
        Path heldTypes = tmpRoot.resolve("api-export-types.h");
        Files.move(typesPath, heldTypes);
        try {
            HttpResponse<String> incomplete = HTTP.send(HttpRequest.newBuilder(URI.create(exportUrl))
                    .header("Authorization", "Bearer exp-rw")
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(409, incomplete.statusCode(), incomplete.body());
            JsonObject failure = JsonParser.parseString(incomplete.body()).getAsJsonObject();
            assertEquals("INCOMPLETE_EXPORT", failure.get("code").getAsString());
            assertTrue(failure.get("error").getAsString().contains("missing types.h"));
            assertEquals(publishedAt, Files.getLastModifiedTime(manifestPath));
        } finally {
            Files.move(heldTypes, typesPath);
        }

        StreamableMcpClient rw = new StreamableMcpClient(server.baseUrl + "/mcp/rw", "export-rw", "exp-rw");
        String targetAddr = rw.callOk("search_code", Map.of("query", "7feb352d", "scope", "pseudocode"))
                .getAsJsonArray("matches").get(0).getAsJsonObject().get("address").getAsString();
        String targetOffset = String.format("%06x", Long.parseLong(targetAddr, 16) - 0x00400000L);
        String expectedSrcFile = "src/" + targetOffset + ".c";
        Path strippedV0 = tmpRoot.resolve("api-export/code/v0");
        assertFalse(Files.exists(strippedV0.resolve("src/_unmapped.c")));
        assertTrue(Files.isRegularFile(strippedV0.resolve(expectedSrcFile)), "Missing " + expectedSrcFile + " in v0");
        assertFalse(Files.readString(strippedV0.resolve(expectedSrcFile), StandardCharsets.UTF_8).contains("mix_renamed"));

        JsonObject entryDis = rw.callOk("disassemble", Map.of("target", "entry", "max_instructions", 30));
        String mainAddr = null;
        for (JsonElement element : entryDis.getAsJsonArray("instructions")) {
            JsonObject instruction = element.getAsJsonObject();
            String mnemonic = instruction.get("mnemonic").getAsString();
            String operands = instruction.get("operands").getAsString();
            if ("MOV".equals(mnemonic) && operands.startsWith("RDI,0x")) {
                mainAddr = operands.substring("RDI,".length()).trim();
                break;
            }
        }
        assertNotNull(mainAddr, "Expected main callback address in entry disassembly");

        rw.callOk("apply_edits", Map.of(
                "expected_version", 0,
                "reason", "define main and rename mix for export check",
                "edits", List.of(
                        Map.of("op", "create_function", "target", mainAddr, "name", "main"),
                        Map.of("op", "rename_function", "target", targetAddr, "new_name", "mix_renamed"))));

        HttpResponse<String> expV1Resp = HTTP.send(HttpRequest.newBuilder(URI.create(exportUrl))
                .header("Authorization", "Bearer exp-rw")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, expV1Resp.statusCode(), expV1Resp.body());
        JsonObject expV1 = JsonParser.parseString(expV1Resp.body()).getAsJsonObject();
        assertEquals(1L, expV1.get("version").getAsLong());
        assertEquals("code/v1", expV1.get("dir").getAsString());
        Path strippedV1 = tmpRoot.resolve("api-export/code/v1");
        assertFalse(Files.exists(strippedV1.resolve("src/_unmapped.c")));
        assertTrue(Files.readString(strippedV1.resolve("functions.jsonl"), StandardCharsets.UTF_8).contains("mix_renamed"));
        assertTrue(Files.readString(strippedV1.resolve(expectedSrcFile), StandardCharsets.UTF_8).contains("mix_renamed"));
        assertTrue(Files.isRegularFile(strippedV1.resolve("src/00119a.c")),
                "Expected export to recover main from the __libc_start_main callback");
        assertTrue(Files.readString(strippedV1.resolve("src/00119a.c"), StandardCharsets.UTF_8).contains("main("));
        server.shutdownAndAwait("exp-rw");
    }

    private static RunningServer startServer(String runName, boolean withBinary, String... options) throws Exception {
        Path workDir = tmpRoot.resolve(runName);
        Files.createDirectories(workDir);
        Path readyFile = workDir.resolve("ready.json");
        String launchId = UUID.randomUUID().toString();

        if ("local".equalsIgnoreCase(MODE)) {
            List<String> cmd = new ArrayList<>(List.of(
                    repoDir.resolve("bin/ghidra-mcp").toString(),
                    "--work-dir", workDir.toString(),
                    "--cache-dir", tmpRoot.resolve("cache").toString(),
                    "--port", "0"));
            if (withBinary) {
                cmd.add("--binary");
                cmd.add(fixturePath.toString());
            }
            cmd.addAll(List.of(options));
            ProcessBuilder builder = new ProcessBuilder(cmd).directory(repoDir.toFile());
            builder.environment().put("GHIDRA_MCP_LAUNCH_ID", launchId);
            RunningServer srv = new RunningServer(builder.start(), null, null, readyFile, launchId);
            STARTED.add(srv);
            srv.awaitReady(null);
            return srv;
        }

        String cname = "ghidra-mcp-e2e-" + ProcessHandle.current().pid() + "-" + System.nanoTime();
        List<String> cmd = new ArrayList<>(List.of(
                ENGINE, "run", "--rm", "--name", cname,
                "-p", "127.0.0.1::8765",
                "-e", "GHIDRA_MCP_LAUNCH_ID=" + launchId,
                "-v", tmpRoot + ":/data",
                IMAGE,
                "--work-dir", "/data/" + runName,
                "--cache-dir", "/data/cache"));
        if (withBinary) {
            cmd.add("--binary");
            cmd.add("/data/input/readability-fixture.elf");
        }
        cmd.addAll(List.of(options));
        Process proc = new ProcessBuilder(cmd).start();
        RunningServer srv = new RunningServer(proc, ENGINE, cname, readyFile, launchId);
        STARTED.add(srv);
        srv.awaitReady(() -> resolveContainerPort(ENGINE, cname));
        return srv;
    }

    private static int resolveContainerPort(String engine, String cname) throws Exception {
        Process p = new ProcessBuilder(engine, "port", cname, "8765/tcp").start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        assertEquals(0, p.waitFor(), "Failed to query container port: " + out);
        String firstLine = out.lines().findFirst().orElseThrow();
        int idx = firstLine.lastIndexOf(':');
        return Integer.parseInt(firstLine.substring(idx + 1).trim());
    }

    private static HttpResponse<String> get(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15)).GET().build();
        return HTTP.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static JsonObject getJson(String url) throws Exception {
        HttpResponse<String> resp = get(url);
        assertEquals(200, resp.statusCode(), "GET " + url + " -> " + resp.body());
        return JsonParser.parseString(resp.body()).getAsJsonObject();
    }

    @FunctionalInterface
    interface PortLookup {
        int port() throws Exception;
    }

    private static final class RunningServer {
        final Process proc;
        final String engine;
        final String containerName;
        final Path readyFile;
        final String launchId;
        JsonObject readyJson;
        String baseUrl;

        RunningServer(Process proc, String engine, String containerName, Path readyFile, String launchId) {
            this.proc = proc;
            this.engine = engine;
            this.containerName = containerName;
            this.readyFile = readyFile;
            this.launchId = launchId;
        }

        void awaitReady(PortLookup portLookup) throws Exception {
            long deadline = System.currentTimeMillis() + 90_000;
            while (System.currentTimeMillis() < deadline) {
                if (!proc.isAlive()) {
                    String out = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    String err = new String(proc.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                    fail("Server exited early (" + proc.exitValue() + ")\nSTDOUT:\n" + out + "\nSTDERR:\n" + err);
                }
                try {
                    JsonObject json = JsonParser.parseString(Files.readString(readyFile)).getAsJsonObject();
                    if ("ready".equals(json.get("status").getAsString())
                            && launchId.equals(json.get("launch_id").getAsString())) {
                        this.readyJson = json;
                        if (portLookup != null) {
                            this.baseUrl = "http://127.0.0.1:" + portLookup.port();
                        } else {
                            this.baseUrl = json.get("api_url").getAsString().replaceFirst("/api/v1$", "");
                        }
                        return;
                    }
                } catch (NoSuchFileException ignored) {
                    // The launcher removes stale readiness before startup.
                }
                Thread.sleep(250);
            }
            fail("Timed out waiting for " + readyFile);
        }

        void shutdownAndAwait() throws Exception {
            shutdownAndAwait(null);
        }

        void shutdownAndAwait(String token) throws Exception {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/shutdown"))
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.noBody());
            if (token != null) b.header("Authorization", "Bearer " + token);
            HttpResponse<String> resp = HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(202, resp.statusCode(), resp.body());
            assertTrue(proc.waitFor(20, TimeUnit.SECONDS), "Server did not exit within 20s");
            assertEquals(0, proc.exitValue());
        }

        void forceStop() {
            if (containerName != null) {
                try { new ProcessBuilder(engine, "rm", "-f", containerName).start().waitFor(5, TimeUnit.SECONDS); }
                catch (Exception ignored) {}
            }
            if (proc.isAlive()) proc.destroyForcibly();
        }
    }

    private record ToolCallResult(boolean isError, JsonObject body) {}

    private static final class StreamableMcpClient {
        private final String url;
        private final String name;
        private final String token;
        private String sessionId;
        private int nextId = 1;

        StreamableMcpClient(String url, String name) throws Exception {
            this(url, name, null);
        }

        StreamableMcpClient(String url, String name, String token) throws Exception {
            this.url = url;
            this.name = name;
            this.token = token;
            JsonObject res = request("initialize", Map.of(
                    "protocolVersion", "2025-03-26",
                    "capabilities", Map.of(),
                    "clientInfo", Map.of("name", this.name, "version", "1.0")));
            assertTrue(res.has("result"), "initialize failed: " + res);
            notify("notifications/initialized", Map.of());
        }

        JsonArray listTools() throws Exception {
            JsonObject res = request("tools/list", Map.of());
            assertTrue(res.has("result"), "tools/list failed: " + res);
            return res.getAsJsonObject("result").getAsJsonArray("tools");
        }

        JsonObject callOk(String toolName, Map<String, Object> args) throws Exception {
            ToolCallResult res = callRaw(toolName, args);
            assertFalse(res.isError(), toolName + " failed: " + res.body());
            return res.body();
        }

        ToolCallResult callRaw(String toolName, Map<String, Object> args) throws Exception {
            JsonObject res = request("tools/call", Map.of("name", toolName, "arguments", args));
            if (res.has("error")) return new ToolCallResult(true, res);
            JsonObject result = res.getAsJsonObject("result");
            boolean isErr = result.has("isError") && result.get("isError").getAsBoolean();
            String text = result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString();
            return new ToolCallResult(isErr, JsonParser.parseString(text).getAsJsonObject());
        }

        private JsonObject request(String method, Map<String, Object> params) throws Exception {
            int id = nextId++;
            return post(Map.of("jsonrpc", "2.0", "id", id, "method", method, "params", params));
        }

        private void notify(String method, Map<String, Object> params) throws Exception {
            post(Map.of("jsonrpc", "2.0", "method", method, "params", params));
        }

        private JsonObject post(Map<String, Object> payload) throws Exception {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(45))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(payload), StandardCharsets.UTF_8));
            if (sessionId != null) b.header("Mcp-Session-Id", sessionId);
            if (token != null) b.header("Authorization", "Bearer " + token);
            HttpResponse<String> resp = HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
            resp.headers().firstValue("Mcp-Session-Id").ifPresent(sid -> sessionId = sid);
            String raw = resp.body();
            if (raw == null || raw.isBlank()) return new JsonObject();
            String ctype = resp.headers().firstValue("Content-Type").orElse("");
            if (ctype.contains("text/event-stream")) {
                for (String line : raw.split("\n")) {
                    if (line.startsWith("data:")) {
                        String chunk = line.substring(5).strip();
                        if (!chunk.isEmpty()) return JsonParser.parseString(chunk).getAsJsonObject();
                    }
                }
                fail("Empty SSE response: " + raw);
            }
            return JsonParser.parseString(raw).getAsJsonObject();
        }
    }
}
