package org.esperware.ghidramcp;

import com.google.gson.Gson;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/** Simple REST + SSE API on /api/v1/* for external WebUI clients. */
final class WebApiServlet extends HttpServlet {
    record ReadyContext(
            VersionStore store,
            InspectService inspect,
            ProgramExporter exporter,
            String mcpRwUrl,
            String mcpRoUrl,
            Runnable shutdownTrigger,
            BooleanSupplier recoveryRequired) {}

    private final Gson gson = new Gson();
    private final long startedAtMs = System.currentTimeMillis();
    private final AtomicReference<String> phase = new AtomicReference<>("analyzing");
    private final AtomicReference<String> errorMsg = new AtomicReference<>();
    private final AtomicReference<ReadyContext> ctxRef = new AtomicReference<>();
    private final Set<Thread> activeSse = ConcurrentHashMap.newKeySet();
    private final Semaphore eventSlots = new Semaphore(16);
    private boolean eventStreamsClosed;

    void markReady(ReadyContext ctx) {
        ctxRef.set(ctx);
        phase.set("ready");
    }

    void markError(String message) {
        errorMsg.set(message);
        phase.set("error");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getRequestURI();
        if (path == null) path = "/";

        if ("/api/v1/health".equals(path)) {
            ReadyContext ctx = ctxRef.get();
            String st = ctx != null && ctx.recoveryRequired().getAsBoolean() ? "recovery_required" : phase.get();
            boolean ok = !"error".equals(st) && !"recovery_required".equals(st);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("ok", ok);
            body.put("status", st);
            if (errorMsg.get() != null) body.put("error", errorMsg.get());
            sendJson(resp, ok ? 200 : 503, body);
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
            if (ctx.recoveryRequired().getAsBoolean()) {
                throw new ApiError("RECOVERY_REQUIRED", "Restart the server to recover the workspace", null);
            }
            if ("/api/v1/status".equals(path)) {
                Map<String, Object> status = new LinkedHashMap<>(ctx.inspect().programInfo());
                status.put("state", phase.get());
                status.put("mcp_rw_url", ctx.mcpRwUrl());
                status.put("mcp_ro_url", ctx.mcpRoUrl());
                status.put("uptime_ms", System.currentTimeMillis() - startedAtMs);
                sendJson(resp, 200, status);
            } else if ("/api/v1/versions".equals(path)) {
                var versions = ctx.store().listVersions();
                sendJson(resp, 200, Map.of(
                        "ok", true,
                        "current_version", versions.getLast().get("version"),
                        "versions", versions));
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
            int code = "RECOVERY_REQUIRED".equals(e.code) ? 503 : e.code.contains("NOT_FOUND") ? 404 : 400;
            sendJson(resp, code, Map.of("ok", false, "code", e.code, "error", e.getMessage()));
        } catch (Exception e) {
            sendJson(resp, 500, Map.of("ok", false, "error", e.getMessage() == null ? "internal error" : e.getMessage()));
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getRequestURI();
        if ("/api/v1/shutdown".equals(path)) {
            ReadyContext ctx = ctxRef.get();
            sendJson(resp, 202, Map.of("ok", true, "shutting_down", true));
            Thread.ofVirtual().start(() -> {
                try { Thread.sleep(50); } catch (InterruptedException ignored) {}
                if (ctx != null && ctx.shutdownTrigger() != null) ctx.shutdownTrigger().run();
            });
            return;
        }
        if ("/api/v1/export".equals(path)) {
            ReadyContext ctx = ctxRef.get();
            if (ctx == null) {
                sendJson(resp, 503, Map.of("ok", false, "status", phase.get(), "error", "Server is still initializing"));
                return;
            }
            try {
                if (ctx.recoveryRequired().getAsBoolean()) {
                    throw new ApiError("RECOVERY_REQUIRED", "Restart the server to recover the workspace", null);
                }
                Map<String, Object> result = new LinkedHashMap<>(ctx.exporter().exportCurrent(ctx.store()));
                result.remove("path");
                sendJson(resp, 200, result);
            } catch (ApiError e) {
                int code = "RECOVERY_REQUIRED".equals(e.code) ? 503 : e.code.contains("NOT_FOUND") ? 404 : 400;
                sendJson(resp, code, Map.of("ok", false, "code", e.code, "error", e.getMessage()));
            } catch (Exception e) {
                sendJson(resp, 500, Map.of("ok", false, "error", e.getMessage() == null ? "internal error" : e.getMessage()));
            }
            return;
        }
        sendJson(resp, 404, Map.of("ok", false, "error", "Not found"));
    }

    private synchronized void handleSse(HttpServletRequest req, HttpServletResponse resp, VersionStore store)
            throws IOException {
        if (eventStreamsClosed || !eventSlots.tryAcquire()) {
            resp.sendError(503, "Too many event streams");
            return;
        }
        resp.setContentType("text/event-stream; charset=utf-8");
        resp.setHeader("Cache-Control", "no-store");

        AsyncContext async;
        try {
            async = req.startAsync();
            async.setTimeout(0);
        } catch (RuntimeException e) {
            eventSlots.release();
            throw e;
        }
        var disconnected = new AtomicBoolean();
        Thread worker = Thread.ofVirtual().unstarted(() -> streamEvents(async, store, disconnected));
        async.addListener(new AsyncListener() {
            @Override public void onComplete(AsyncEvent e) { disconnect(); }
            @Override public void onError(AsyncEvent e) { disconnect(); }
            @Override public void onTimeout(AsyncEvent e) { disconnect(); }
            @Override public void onStartAsync(AsyncEvent e) {}

            private void disconnect() {
                disconnected.set(true);
                worker.interrupt();
            }
        });
        activeSse.add(worker);
        worker.start();
    }

    private void streamEvents(AsyncContext async, VersionStore store, AtomicBoolean disconnected) {
        Thread worker = Thread.currentThread();
        var events = new ArrayBlockingQueue<VersionStore.SseEvent>(16);
        try (var subscription = store.subscribe(event -> {
            if (!events.offer(event)) worker.interrupt();
        })) {
            if (disconnected.get() || worker.isInterrupted()) return;
            var out = async.getResponse().getOutputStream();
            writeEvent(out, new VersionStore.SseEvent("status", Map.of(
                    "state", phase.get(), "version", store.currentVersion())));
            while (!disconnected.get() && !worker.isInterrupted()) {
                var event = events.poll(5, TimeUnit.SECONDS);
                if (event == null) {
                    out.write(": keepalive\n\n".getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } else {
                    writeEvent(out, event);
                }
            }
        } catch (IOException | InterruptedException ignored) {
            // The client disconnected or its queue filled up.
        } catch (Exception e) {
            getServletContext().log("Event stream failed", e);
        } finally {
            activeSse.remove(worker);
            eventSlots.release();
            try { async.complete(); } catch (IllegalStateException ignored) {}
        }
    }

    private void writeEvent(jakarta.servlet.ServletOutputStream out, VersionStore.SseEvent event) throws IOException {
        String message = "event: " + event.type() + "\ndata: " + gson.toJson(event.data()) + "\n\n";
        out.write(message.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    synchronized void closeSse() {
        eventStreamsClosed = true;
        activeSse.forEach(Thread::interrupt);
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

}
