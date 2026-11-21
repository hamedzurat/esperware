package org.esperware.ghidramcp;

import com.google.gson.Gson;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/** Simple REST + SSE API on /api/v1/* for external WebUI clients. */
final class WebApiServlet extends HttpServlet {
    record ReadyContext(
            ProgramWorkspace workspace,
            VersionStore store,
            InspectService inspect,
            String mcpRwUrl,
            String mcpRoUrl,
            Runnable shutdownTrigger) {}

    private final Gson gson = new Gson();
    private final String corsOrigin;
    private final long startedAtMs = System.currentTimeMillis();
    private final AtomicReference<String> phase = new AtomicReference<>("analyzing");
    private final AtomicReference<String> errorMsg = new AtomicReference<>();
    private final AtomicReference<ReadyContext> ctxRef = new AtomicReference<>();
    private final Set<AsyncContext> activeSse = ConcurrentHashMap.newKeySet();

    WebApiServlet(String corsOrigin) {
        this.corsOrigin = (corsOrigin == null || corsOrigin.isBlank()) ? "*" : corsOrigin;
    }

    void markReady(ReadyContext ctx) {
        ctxRef.set(ctx);
        phase.set("ready");
    }

    void markError(String message) {
        errorMsg.set(message);
        phase.set("error");
    }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) {
        addCors(resp);
        resp.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        resp.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        resp.setStatus(204);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        addCors(resp);
        String path = req.getRequestURI();
        if (path == null) path = "/";

        if ("/api/v1/health".equals(path)) {
            String st = phase.get();
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("ok", !"error".equals(st));
            body.put("status", st);
            if (errorMsg.get() != null) body.put("error", errorMsg.get());
            sendJson(resp, "error".equals(st) ? 503 : 200, body);
            return;
        }

        if (!path.startsWith("/api/")) {
            sendJson(resp, 404, Map.of("ok", false, "error", "API route not found"));
            return;
        }

        ReadyContext ctx = ctxRef.get();
        if (ctx == null) {
            sendJson(resp, 503, Map.of("ok", false, "status", phase.get(), "error", "Server is still initializing"));
            return;
        }

        try {
            if ("/api/v1/status".equals(path)) {
                Map<String, Object> status = new LinkedHashMap<>(ctx.inspect().programInfo());
                status.put("state", phase.get());
                status.put("mcp_rw_url", ctx.mcpRwUrl());
                status.put("mcp_ro_url", ctx.mcpRoUrl());
                status.put("uptime_ms", System.currentTimeMillis() - startedAtMs);
                sendJson(resp, 200, status);
            } else if ("/api/v1/versions".equals(path)) {
                sendJson(resp, 200, Map.of(
                        "ok", true,
                        "current_version", ctx.store().currentVersion(),
                        "versions", ctx.store().listVersions()));
            } else if (path.startsWith("/api/v1/versions/")) {
                long v = Long.parseLong(path.substring("/api/v1/versions/".length()));
                Map<String, Object> detail = ctx.store().getVersion(v);
                if (detail == null) sendJson(resp, 404, Map.of("ok", false, "error", "Version not found"));
                else sendJson(resp, 200, Map.of("ok", true, "version", detail));
            } else if ("/api/v1/diff".equals(path)) {
                long current = ctx.store().currentVersion();
                long from = parseLongParam(req, "from", 0L);
                long to = parseLongParam(req, "to", current);
                String fn = req.getParameter("function");
                if (fn != null && fn.isBlank()) fn = null;
                Map<String, Object> diff = new LinkedHashMap<>(ctx.store().diffRange(from, to, fn));
                diff.put("ok", true);
                sendJson(resp, 200, diff);
            } else if ("/api/v1/functions".equals(path)) {
                Map<String, Object> args = new LinkedHashMap<>();
                if (req.getParameter("filter") != null) args.put("filter", req.getParameter("filter"));
                if (req.getParameter("sort") != null) args.put("sort", req.getParameter("sort"));
                if (req.getParameter("cursor") != null) args.put("cursor", req.getParameter("cursor"));
                if (req.getParameter("limit") != null) args.put("limit", Integer.parseInt(req.getParameter("limit")));
                sendJson(resp, 200, ctx.inspect().listFunctions(args));
            } else if (path.startsWith("/api/v1/functions/")) {
                String target = URLDecoder.decode(path.substring("/api/v1/functions/".length()), StandardCharsets.UTF_8);
                Map<String, Object> out = new LinkedHashMap<>(ctx.inspect().decompile(Map.of("target", target)));
                if ("true".equalsIgnoreCase(req.getParameter("disasm"))) {
                    out.put("disassembly", ctx.inspect().disassemble(Map.of("target", target)));
                }
                sendJson(resp, 200, out);
            } else if ("/api/v1/events".equals(path)) {
                handleSse(req, resp, ctx.store());
            } else {
                sendJson(resp, 404, Map.of("ok", false, "error", "Not found"));
            }
        } catch (NumberFormatException e) {
            sendJson(resp, 400, Map.of("ok", false, "error", "Invalid numeric parameter"));
        } catch (ApiError e) {
            int code = e.code.contains("NOT_FOUND") ? 404 : 400;
            sendJson(resp, code, Map.of("ok", false, "code", e.code, "error", e.getMessage()));
        } catch (Exception e) {
            sendJson(resp, 500, Map.of("ok", false, "error", e.getMessage() == null ? "internal error" : e.getMessage()));
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        addCors(resp);
        if ("/api/v1/shutdown".equals(req.getRequestURI())) {
            ReadyContext ctx = ctxRef.get();
            sendJson(resp, 202, Map.of("ok", true, "shutting_down", true));
            Thread.ofVirtual().start(() -> {
                try { Thread.sleep(50); } catch (InterruptedException ignored) {}
                if (ctx != null && ctx.shutdownTrigger() != null) ctx.shutdownTrigger().run();
            });
            return;
        }
        sendJson(resp, 404, Map.of("ok", false, "error", "Not found"));
    }

    private void handleSse(HttpServletRequest req, HttpServletResponse resp, VersionStore store) throws IOException {
        resp.setStatus(200);
        resp.setContentType("text/event-stream; charset=utf-8");
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Connection", "keep-alive");
        resp.flushBuffer();

        AsyncContext async = req.startAsync();
        async.setTimeout(0);
        activeSse.add(async);
        PrintWriter writer = resp.getWriter();
        writer.write("event: status\ndata: " + gson.toJson(Map.of(
                "state", phase.get(), "version", store.currentVersion())) + "\n\n");
        writer.flush();

        Object writeLock = new Object();
        AutoCloseable[] subHolder = new AutoCloseable[1];
        subHolder[0] = store.subscribe(evt -> {
            synchronized (writeLock) {
                if (writer.checkError()) {
                    closeQuietly(subHolder[0]);
                    activeSse.remove(async);
                    try { async.complete(); } catch (Exception ignored) {}
                    return;
                }
                writer.write("event: " + evt.type() + "\ndata: " + gson.toJson(evt.data()) + "\n\n");
                writer.flush();
            }
        });

        async.addListener(new jakarta.servlet.AsyncListener() {
            @Override public void onComplete(jakarta.servlet.AsyncEvent e) { activeSse.remove(async); closeQuietly(subHolder[0]); }
            @Override public void onTimeout(jakarta.servlet.AsyncEvent e) { activeSse.remove(async); closeQuietly(subHolder[0]); async.complete(); }
            @Override public void onError(jakarta.servlet.AsyncEvent e) { activeSse.remove(async); closeQuietly(subHolder[0]); }
            @Override public void onStartAsync(jakarta.servlet.AsyncEvent e) {}
        });
    }

    void closeSse() {
        for (AsyncContext async : List.copyOf(activeSse)) {
            activeSse.remove(async);
            try { async.complete(); } catch (Exception ignored) {}
        }
    }

    private void addCors(HttpServletResponse resp) {
        resp.setHeader("Access-Control-Allow-Origin", corsOrigin);
    }

    private void sendJson(HttpServletResponse resp, int status, Object body) throws IOException {
        byte[] bytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        resp.setStatus(status);
        resp.setContentType("application/json; charset=utf-8");
        resp.setHeader("Cache-Control", "no-store");
        resp.setContentLength(bytes.length);
        resp.getOutputStream().write(bytes);
    }

    private static long parseLongParam(HttpServletRequest req, String name, long def) {
        String raw = req.getParameter(name);
        return (raw == null || raw.isBlank()) ? def : Long.parseLong(raw.trim());
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c != null) try { c.close(); } catch (Exception ignored) {}
    }
}
