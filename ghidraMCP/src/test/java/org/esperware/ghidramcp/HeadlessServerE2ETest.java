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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
        fixturePath = artifactsDir.resolve("build/readability-fixture.elf");

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
        RunningServer srv1 = startServer("run-1", true);
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

        JsonObject dis = ro.callOk("disassemble", Map.of("target", transformAddr, "max_instructions", 10));
        JsonArray insns = dis.getAsJsonArray("instructions");
        assertTrue(insns.size() > 0);
        StringBuilder pat = new StringBuilder();
        for (int i = 0; i < Math.min(2, insns.size()); i++) {
            pat.append(insns.get(i).getAsJsonObject().get("bytes").getAsString());
        }
        String firstBytes = pat.substring(0, Math.min(6, pat.length()));

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

        JsonObject batch = rw.callOk("apply_edits", Map.of(
                "expected_version", 1,
                "reason", "clean up transform",
                "edits", List.of(
                        Map.of("op", "rename_function", "target", transformAddr, "new_name", "transform_fn"),
                        Map.of("op", "rename_var", "function", transformAddr, "var_name", localVar, "new_name", "mixed_state"),
                        Map.of("op", "set_comment", "target", transformAddr, "comment_type", "function", "text", "Transforms input via mix()"),
                        Map.of("op", "set_comment", "target", transformAddr, "comment_type", "pre", "text", "Entry pre-comment"))));
        assertEquals(2L, batch.get("version").getAsLong());
        String stepDiff = batch.getAsJsonArray("diffs").get(0).getAsJsonObject().get("diff").getAsString();
        assertTrue(stepDiff.contains("transform_fn"));
        assertTrue(stepDiff.contains("mixed_state"));

        // Stale expected_version fails without advancing version
        var stale = rw.callRaw("apply_edits", Map.of(
                "expected_version", 0,
                "edits", List.of(Map.of("op", "rename_function", "target", transformAddr, "new_name", "nope"))));
        assertTrue(stale.isError());
        assertEquals("STALE_VERSION", stale.body().getAsJsonObject("error").get("code").getAsString());

        JsonObject chk = rw.callOk("save_checkpoint", Map.of("label", "after-transform"));
        assertEquals(2L, chk.get("version").getAsLong());

        // 3. REST + CORS (for external wui/) + SSE checks
        HttpResponse<String> rootResp = get(baseUrl + "/");
        assertEquals(404, rootResp.statusCode());

        HttpResponse<String> statusResp = get(apiUrl + "/status");
        assertEquals(200, statusResp.statusCode());
        assertEquals("*", statusResp.headers().firstValue("Access-Control-Allow-Origin").orElse(""));

        JsonObject versions = getJson(apiUrl + "/versions");
        assertEquals(2L, versions.get("current_version").getAsLong());
        assertEquals(3, versions.getAsJsonArray("versions").size());
        JsonObject v2Summary = versions.getAsJsonArray("versions").get(2).getAsJsonObject();
        assertFalse(v2Summary.has("before_c"));
        assertEquals("after-transform", v2Summary.get("checkpoint_label").getAsString());

        JsonObject cumDiff = getJson(apiUrl + "/diff?from=0&to=2");
        assertTrue(cumDiff.getAsJsonArray("diffs").get(0).getAsJsonObject()
                .get("diff").getAsString().contains("+/* Transforms input via mix() */"));

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
            assertTrue(l2.contains("\"version\":2"), l2);
        }

        // 4. Graceful shutdown -> restart on same work-dir -> cross-restart revert to v0
        srv1.shutdownAndAwait();
        assertFalse(Files.exists(tmpRoot.resolve("run-1/ready.json")));

        RunningServer srv2 = startServer("run-1", false);
        assertEquals(2L, srv2.readyJson.get("current_version").getAsLong());
        StreamableMcpClient rw2 = new StreamableMcpClient(srv2.baseUrl + "/mcp/rw", "main-rw-2");
        JsonObject reverted = rw2.callOk("revert", Map.of(
                "to_version", 0, "expected_version", 2, "reason", "full rollback test"));
        assertEquals(3L, reverted.get("version").getAsLong());

        JsonObject afterDec = rw2.callOk("decompile", Map.of("target", transformAddr));
        assertFalse(afterDec.get("pseudocode").getAsString().contains("transform_fn"));
        assertFalse(afterDec.get("pseudocode").getAsString().contains("mixed_state"));
        JsonObject afterTypes = rw2.callOk("get_type", Map.of("query", "ProbeState", "exact", true));
        assertEquals(0, afterTypes.get("total").getAsInt());
        srv2.shutdownAndAwait();

        // 5. Cache hit on fresh run-2
        String sha = srv1.readyJson.get("binary_sha256").getAsString();
        assertTrue(Files.exists(tmpRoot.resolve("cache").resolve(sha).resolve("workspace.gpr")));
        RunningServer srv3 = startServer("run-2-cached", true);
        assertEquals(0L, srv3.readyJson.get("current_version").getAsLong());
        assertEquals(sha, srv3.readyJson.get("binary_sha256").getAsString());
        srv3.shutdownAndAwait();
    }

    private static RunningServer startServer(String runName, boolean withBinary) throws Exception {
        Path workDir = tmpRoot.resolve(runName);
        Files.createDirectories(workDir);
        Path readyFile = workDir.resolve("ready.json");
        Files.deleteIfExists(readyFile);

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
            Process proc = new ProcessBuilder(cmd).directory(repoDir.toFile()).start();
            RunningServer srv = new RunningServer(proc, null, null, readyFile);
            STARTED.add(srv);
            srv.awaitReady(null);
            return srv;
        }

        String cname = "ghidra-mcp-e2e-" + ProcessHandle.current().pid() + "-" + System.nanoTime();
        List<String> cmd = new ArrayList<>(List.of(
                ENGINE, "run", "--rm", "--name", cname,
                "-p", "127.0.0.1::8765",
                "-v", tmpRoot + ":/data",
                IMAGE,
                "--work-dir", "/data/" + runName,
                "--cache-dir", "/data/cache"));
        if (withBinary) {
            cmd.add("--binary");
            cmd.add("/data/input/readability-fixture.elf");
        }
        Process proc = new ProcessBuilder(cmd).start();
        RunningServer srv = new RunningServer(proc, ENGINE, cname, readyFile);
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
        JsonObject readyJson;
        String baseUrl;

        RunningServer(Process proc, String engine, String containerName, Path readyFile) {
            this.proc = proc;
            this.engine = engine;
            this.containerName = containerName;
            this.readyFile = readyFile;
        }

        void awaitReady(PortLookup portLookup) throws Exception {
            long deadline = System.currentTimeMillis() + 90_000;
            while (System.currentTimeMillis() < deadline) {
                if (!proc.isAlive()) {
                    String out = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    String err = new String(proc.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                    fail("Server exited early (" + proc.exitValue() + ")\nSTDOUT:\n" + out + "\nSTDERR:\n" + err);
                }
                if (Files.exists(readyFile)) {
                    String txt = Files.readString(readyFile, StandardCharsets.UTF_8).trim();
                    if (!txt.isEmpty()) {
                        JsonObject json = JsonParser.parseString(txt).getAsJsonObject();
                        if ("ready".equals(json.get("status").getAsString())) {
                            this.readyJson = json;
                            if (portLookup != null) {
                                this.baseUrl = "http://127.0.0.1:" + portLookup.port();
                            } else {
                                this.baseUrl = json.get("api_url").getAsString().replaceFirst("/api/v1$", "");
                            }
                            return;
                        }
                    }
                }
                Thread.sleep(250);
            }
            fail("Timed out waiting for " + readyFile);
        }

        void shutdownAndAwait() throws Exception {
            HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/shutdown"))
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
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
        private String sessionId;
        private int nextId = 1;

        StreamableMcpClient(String url, String name) throws Exception {
            this.url = url;
            this.name = name;
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
