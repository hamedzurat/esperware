package org.esperware.ghidramcp;

import com.google.gson.Gson;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
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
    private final AtomicReference<Runnable> shutdownTriggerRef = new AtomicReference<>();
    private final Set<Thread> activeSse = ConcurrentHashMap.newKeySet();
    private final Semaphore eventSlots = new Semaphore(16);
    private boolean eventStreamsClosed;

    void setShutdownTrigger(Runnable shutdownTrigger) {
        shutdownTriggerRef.set(shutdownTrigger);
    }

    void markReady(ReadyContext ctx) {
        ctxRef.set(ctx);
        if (ctx.shutdownTrigger() != null) shutdownTriggerRef.set(ctx.shutdownTrigger());
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
                        "current_version", ctx.store().currentVersion(),
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
                putStr(args, "filter", req.getParameter("filter"));
                putStr(args, "sort", req.getParameter("sort"));
                putStr(args, "cursor", req.getParameter("cursor"));
                putInt(args, "limit", req.getParameter("limit"));
                sendJson(resp, 200, ctx.inspect().listFunctions(args));
            } else if (path.startsWith("/api/v1/functions/")) {
                String target = decodePathSegment(path.substring("/api/v1/functions/".length()));
                Map<String, Object> decompileArgs = new LinkedHashMap<>();
                decompileArgs.put("target", target);
                putInt(decompileArgs, "offset", req.getParameter("offset"));
                Map<String, Object> out = new LinkedHashMap<>(ctx.inspect().decompile(decompileArgs));
                if ("true".equalsIgnoreCase(req.getParameter("disasm"))) {
                    Map<String, Object> disasmArgs = new LinkedHashMap<>();
                    disasmArgs.put("target", target);
                    putStr(disasmArgs, "cursor", req.getParameter("disasm_cursor"));
                    putInt(disasmArgs, "max_instructions", req.getParameter("max_instructions"));
                    out.put("disassembly", ctx.inspect().disassemble(disasmArgs));
                }
                sendJson(resp, 200, out);
            } else if ("/api/v1/symbols".equals(path)) {
                Map<String, Object> args = new LinkedHashMap<>();
                putStr(args, "kind", req.getParameter("kind"));
                putStr(args, "filter", req.getParameter("filter"));
                putStr(args, "cursor", req.getParameter("cursor"));
                putInt(args, "limit", req.getParameter("limit"));
                sendJson(resp, 200, ctx.inspect().listSymbols(args));
            } else if ("/api/v1/xrefs".equals(path)) {
                Map<String, Object> args = new LinkedHashMap<>();
                putStr(args, "target", req.getParameter("target"));
                putStr(args, "kind", req.getParameter("kind"));
                putStr(args, "cursor", req.getParameter("cursor"));
                putInt(args, "limit", req.getParameter("limit"));
                sendJson(resp, 200, ctx.inspect().getXrefs(args));
            } else if ("/api/v1/memory".equals(path)) {
                Map<String, Object> args = new LinkedHashMap<>();
                putStr(args, "address", req.getParameter("address"));
                putInt(args, "size", req.getParameter("size"));
                putStr(args, "format", req.getParameter("format"));
                sendJson(resp, 200, ctx.inspect().readMemory(args));
            } else if ("/api/v1/search".equals(path)) {
                Map<String, Object> args = new LinkedHashMap<>();
                putStr(args, "query", req.getParameter("query"));
                putStr(args, "scope", req.getParameter("scope"));
                putStr(args, "cursor", req.getParameter("cursor"));
                putInt(args, "limit", req.getParameter("limit"));
                sendJson(resp, 200, ctx.inspect().searchCode(args));
            } else if ("/api/v1/types".equals(path)) {
                Map<String, Object> args = new LinkedHashMap<>();
                putStr(args, "query", req.getParameter("query"));
                if (req.getParameter("exact") != null) {
                    args.put("exact", "true".equalsIgnoreCase(req.getParameter("exact")));
                }
                putStr(args, "cursor", req.getParameter("cursor"));
                putInt(args, "limit", req.getParameter("limit"));
                sendJson(resp, 200, ctx.inspect().getType(args));
            } else if ("/api/v1/events".equals(path)) {
                handleSse(req, resp, ctx.store());
            } else {
                sendJson(resp, 404, Map.of("ok", false, "error", "Not found"));
            }
        } catch (NumberFormatException e) {
            sendJson(resp, 400, Map.of("ok", false, "error", "Invalid numeric parameter"));
        } catch (Exception e) {
            sendFailure(resp, e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getRequestURI();
        if ("/api/v1/shutdown".equals(path)) {
            Runnable trigger = shutdownTriggerRef.get();
            sendJson(resp, 202, Map.of("ok", true, "shutting_down", true));
            Thread.ofVirtual().start(() -> {
                try { Thread.sleep(50); } catch (InterruptedException ignored) {}
                if (trigger != null) trigger.run();
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
            } catch (Exception e) {
                sendFailure(resp, e);
            }
            return;
        }
        sendJson(resp, 404, Map.of("ok", false, "error", "Not found"));
    }

    private synchronized void handleSse(HttpServletRequest req, HttpServletResponse resp, VersionStore store)
            throws IOException {
        if (eventStreamsClosed || !eventSlots.tryAcquire()) {
            sendJson(resp, 503, Map.of("ok", false, "code", "TOO_MANY_STREAMS", "error", "Too many event streams"));
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

    private void sendFailure(HttpServletResponse resp, Exception failure) throws IOException {
        if (failure instanceof ApiError e) {
            int code = switch (e.code) {
                case "RECOVERY_REQUIRED", "DECOMPILER_BUSY" -> 503;
                case "INCOMPLETE_EXPORT", "STALE_VERSION" -> 409;
                default -> e.code.contains("NOT_FOUND") ? 404 : 400;
            };
            String msg = e.getMessage() == null ? e.code : e.getMessage();
            sendJson(resp, code, Map.of("ok", false, "code", e.code, "error", msg));
        } else {
            String message = failure.getMessage();
            sendJson(resp, 500, Map.of("ok", false, "error", message == null ? "internal error" : message));
        }
    }

    private void sendJson(HttpServletResponse resp, int status, Object body) throws IOException {
        byte[] bytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        resp.setStatus(status);
        resp.setContentType("application/json; charset=utf-8");
        resp.setHeader("Cache-Control", "no-store");
        resp.setContentLength(bytes.length);
        resp.getOutputStream().write(bytes);
    }

    static String decodePathSegment(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        return URLDecoder.decode(raw.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static long parseLongParam(HttpServletRequest req, String name, long def) {
        String raw = req.getParameter(name);
        return (raw == null || raw.isBlank()) ? def : Long.parseLong(raw.trim());
    }

    private static void putStr(Map<String, Object> args, String key, String val) {
        if (val != null) args.put(key, val);
    }

    static boolean isLoopbackOrigin(String origin) {
        if (origin == null || origin.isBlank() || "null".equalsIgnoreCase(origin)) return false;
        URI uri;
        try {
            uri = URI.create(origin);
        } catch (IllegalArgumentException e) {
            return false;
        }
        String scheme = uri.getScheme();
        if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) return false;
        if (uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) return false;
        int port = uri.getPort();
        if (port == 0 || port > 65535) return false;
        String path = uri.getRawPath();
        if (path != null && !path.isEmpty()) return false;
        String host = uri.getHost();
        if (host == null) return false;
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        return Set.of("127.0.0.1", "localhost", "::1").contains(host.toLowerCase(Locale.ROOT));
    }

    private static void putInt(Map<String, Object> args, String key, String val) {
        if (val != null && !val.isBlank()) args.put(key, Integer.parseInt(val.trim()));
    }

}
