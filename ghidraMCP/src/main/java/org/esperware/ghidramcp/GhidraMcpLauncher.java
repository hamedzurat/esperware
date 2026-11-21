package org.esperware.ghidramcp;

import com.google.gson.Gson;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.Msg;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Set;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/** Headless Ghidra entry point hosting /mcp/rw, /mcp/ro, and /api/v1/* on one Jetty port. */
public final class GhidraMcpLauncher implements GhidraLaunchable {
    private static final Set<String> LOOPBACK_HOSTS = Set.of("127.0.0.1", "localhost", "::1");
    private static final Set<String> WILDCARD_HOSTS = Set.of("0.0.0.0", "::");

    public GhidraMcpLauncher() {}

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        Config cfg = Config.parse(args);
        Path readyFile = cfg.workDir.resolve("ready.json");
        Files.createDirectories(cfg.workDir);
        Files.deleteIfExists(readyFile);

        ProxyServlet rwProxy = new ProxyServlet();
        ProxyServlet roProxy = new ProxyServlet();
        WebApiServlet webApi = new WebApiServlet();

        Server jetty = new Server();
        ServerConnector connector = new ServerConnector(jetty);
        connector.setHost(cfg.host);
        connector.setPort(cfg.port);
        jetty.addConnector(connector);

        ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
        ctx.setContextPath("/");
        ServletHolder rwHolder = new ServletHolder(rwProxy);
        rwHolder.setAsyncSupported(true);
        ctx.addServlet(rwHolder, "/mcp/rw");

        ServletHolder roHolder = new ServletHolder(roProxy);
        roHolder.setAsyncSupported(true);
        ctx.addServlet(roHolder, "/mcp/ro");

        ServletHolder apiHolder = new ServletHolder(webApi);
        apiHolder.setAsyncSupported(true);
        ctx.addServlet(apiHolder, "/");

        FilterHolder access = new FilterHolder(accessFilter(cfg));
        access.setAsyncSupported(true);
        ctx.addFilter(access, "/*", EnumSet.of(DispatcherType.REQUEST));

        jetty.setHandler(ctx);
        jetty.setStopTimeout(1000);
        jetty.start();
        int boundPort = connector.getLocalPort();
        String bindHost = normalizeHost(cfg.host);
        String advertisedHost = switch (bindHost) {
            case "0.0.0.0" -> "127.0.0.1";
            case "::" -> "[::1]";
            default -> bindHost.contains(":") ? "[" + bindHost + "]" : bindHost;
        };
        String baseUrl = (cfg.publicUrl != null && !cfg.publicUrl.isBlank())
                ? cfg.publicUrl.replaceAll("/+$", "")
                : "http://" + advertisedHost + ":" + boundPort;

        AtomicReference<ProgramWorkspace> wsRef = new AtomicReference<>();
        AtomicReference<VersionStore> storeRef = new AtomicReference<>();
        AtomicReference<McpEndpoints> mcpRef = new AtomicReference<>();
        AtomicBoolean cleanedUp = new AtomicBoolean(false);

        Runnable cleanup = () -> {
            if (!cleanedUp.compareAndSet(false, true)) return;
            try { Files.deleteIfExists(readyFile); } catch (Exception ignored) {}
            webApi.closeSse();
            try { if (mcpRef.get() != null) mcpRef.get().close(); } catch (Exception ignored) {}
            try { if (!jetty.isStopped()) jetty.stop(); } catch (Exception ignored) {}
            try { if (storeRef.get() != null) storeRef.get().close(); } catch (Exception ignored) {}
            try { if (wsRef.get() != null) wsRef.get().close(); } catch (Exception ignored) {}
        };
        Runnable shutdownTrigger = () -> {
            webApi.closeSse();
            try { jetty.stop(); } catch (Exception ignored) {}
        };
        Runtime.getRuntime().addShutdownHook(new Thread(cleanup, "ghidra-mcp-shutdown"));

        try {
            if (!Application.isInitialized()) {
                Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
            }

            ProgramWorkspace ws = ProgramWorkspace.open(cfg.binary, cfg.workDir, cfg.cacheDir, cfg.poolSize);
            wsRef.set(ws);

            VersionStore store = new VersionStore(cfg.workDir.resolve("history.sqlite"));
            storeRef.set(store);
            store.ensureBaseline(Map.of(
                    "binary_name", ws.binaryName(),
                    "binary_sha256", ws.binarySha256(),
                    "ghidra_version", ws.ghidraVersion(),
                    "arch", ws.program().getLanguageID().getIdAsString()));
            store.recover(ws.savedVersion(), ws::saveVersion);
            ws.versionPublished();

            InspectService inspect = new InspectService(ws, store);
            EditService edit = new EditService(ws, store);
            McpEndpoints mcp = new McpEndpoints(inspect, edit);
            mcpRef.set(mcp);

            rwProxy.attach(mcp.rwTransport());
            roProxy.attach(mcp.roTransport());
            webApi.markReady(new WebApiServlet.ReadyContext(
                    store, inspect, baseUrl + "/mcp/rw", baseUrl + "/mcp/ro", shutdownTrigger, ws::recoveryRequired));

            Map<String, Object> ready = new LinkedHashMap<>();
            ready.put("status", "ready");
            ready.put("pid", ProcessHandle.current().pid());
            ready.put("binary_name", ws.binaryName());
            ready.put("binary_sha256", ws.binarySha256());
            ready.put("current_version", store.currentVersion());
            ready.put("mcp_rw_url", baseUrl + "/mcp/rw");
            ready.put("mcp_ro_url", baseUrl + "/mcp/ro");
            ready.put("api_url", baseUrl + "/api/v1");

            String jsonLine = new Gson().toJson(ready);
            writeAtomically(readyFile, jsonLine + "\n");
            System.out.println(jsonLine);
            System.out.flush();
        } catch (Exception initFailure) {
            webApi.markError(initFailure.getMessage());
            Msg.error(this, "Failed to initialize headless Ghidra MCP", initFailure);
            cleanup.run();
            throw initFailure;
        }

        jetty.join();
        cleanup.run();
        System.exit(0);
    }

    private static Filter accessFilter(Config cfg) {
        URI publicUrl = cfg.publicUrl == null ? null : URI.create(cfg.publicUrl);
        String publicHost = publicUrl == null ? null : normalizeHost(publicUrl.getHost());
        String bindHost = normalizeHost(cfg.host);
        String publicOrigin = publicUrl == null ? null : publicUrl.getScheme() + "://" + publicUrl.getRawAuthority();
        return (request, response, chain) -> {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse resp = (HttpServletResponse) response;
            URI authority = parseRequestAuthority(req);
            String hostName = authority == null ? "" : normalizeHost(authority.getHost());
            if (authority == null || WILDCARD_HOSTS.contains(hostName)
                    || !(LOOPBACK_HOSTS.contains(hostName) || hostName.equals(bindHost) || hostName.equals(publicHost))) {
                resp.sendError(403, "Host is not allowed");
                return;
            }
            String origin = req.getHeader("Origin");
            resp.addHeader("Vary", "Origin");
            if (origin != null) {
                String requestOrigin = req.getScheme() + "://" + authority.getRawAuthority();
                if (!(origin.equalsIgnoreCase(requestOrigin) || origin.equalsIgnoreCase(publicOrigin)
                        || origin.equalsIgnoreCase(cfg.corsOrigin))) {
                    resp.sendError(403, "Origin is not allowed");
                    return;
                }
                resp.setHeader("Access-Control-Allow-Origin", origin);
            }

            String path = req.getServletPath();
            boolean writeRoute = "/mcp/rw".equals(path) || "/api/v1/shutdown".equals(path);
            boolean readRoute = "/mcp/ro".equals(path)
                    || (path.startsWith("/api/v1/") && !"/api/v1/health".equals(path));
            if (origin != null && (writeRoute || readRoute || "/api/v1/health".equals(path))) {
                resp.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
                if ("OPTIONS".equals(req.getMethod())) {
                    resp.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
                    resp.setHeader("Access-Control-Allow-Headers",
                            "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID");
                    resp.setStatus(204);
                    return;
                }
            }
            boolean tokensConfigured = cfg.rwToken != null || cfg.roToken != null;
            if (tokensConfigured && (writeRoute || readRoute)) {
                String auth = req.getHeader("Authorization");
                String token = (auth != null && auth.startsWith("Bearer ")) ? auth.substring(7) : null;
                if (!(tokenMatches(cfg.rwToken, token) || (!writeRoute && tokenMatches(cfg.roToken, token)))) {
                    resp.setStatus(401);
                    resp.setHeader("WWW-Authenticate", "Bearer");
                    resp.setContentType("application/json");
                    resp.getWriter().write("{\"ok\":false,\"error\":\"Unauthorized\"}");
                    return;
                }
            }
            chain.doFilter(request, response);
        };
    }

    private static URI parseRequestAuthority(HttpServletRequest req) {
        String host = req.getHeader("Host");
        if (host == null || host.isBlank()) return null;
        URI uri;
        try {
            uri = URI.create(req.getScheme() + "://" + host);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (uri.getHost() == null || uri.getRawUserInfo() != null || !host.equals(uri.getRawAuthority())) return null;
        int port = uri.getPort();
        if (port == -1) port = "https".equals(req.getScheme()) ? 443 : 80;
        return port > 0 && port <= 65535 && port == req.getServerPort()
                && normalizeHost(uri.getHost()).equals(normalizeHost(req.getServerName())) ? uri : null;
    }

    private static String normalizeHost(String host) {
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        return host.toLowerCase(Locale.ROOT);
    }

    private static boolean tokenMatches(String expected, String presented) {
        return expected != null && presented != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeAtomically(Path target, String content) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static final class ProxyServlet extends HttpServlet {
        private final AtomicReference<HttpServlet> target = new AtomicReference<>();
        private volatile ServletConfig savedConfig;

        @Override
        public void init(ServletConfig config) throws ServletException {
            super.init(config);
            savedConfig = config;
        }

        void attach(HttpServlet delegate) throws ServletException {
            if (savedConfig != null) delegate.init(savedConfig);
            target.set(delegate);
        }

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            HttpServlet delegate = target.get();
            if (delegate == null) {
                resp.setStatus(503);
                resp.setContentType("application/json");
                resp.getWriter().write("{\"ok\":false,\"error\":\"Server initializing\"}");
                return;
            }
            delegate.service(req, resp);
        }
    }

    private record Config(
            Path binary,
            Path workDir,
            Path cacheDir,
            String host,
            int port,
            String publicUrl,
            String corsOrigin,
            int poolSize,
            String rwToken,
            String roToken) {

        static Config parse(String[] args) {
            Path binary = null;
            Path workDir = null;
            String envCache = System.getenv("GHIDRA_MCP_CACHE_DIR");
            Path cacheDir = envCache != null && !envCache.isBlank() ? Path.of(envCache) : null;
            boolean noCache = false;
            String host = System.getenv().getOrDefault("GHIDRA_MCP_HOST", "127.0.0.1");
            int port = Integer.parseInt(System.getenv().getOrDefault("GHIDRA_MCP_PORT", "8765"));
            String publicUrl = System.getenv("GHIDRA_MCP_PUBLIC_URL");
            String corsOrigin = System.getenv("GHIDRA_MCP_CORS_ORIGIN");
            int poolSize = 2;
            String rwToken = System.getenv("GHIDRA_MCP_RW_TOKEN");
            String roToken = System.getenv("GHIDRA_MCP_RO_TOKEN");

            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--binary" -> binary = Path.of(requireArg(args, ++i, "--binary"));
                    case "--work-dir" -> workDir = Path.of(requireArg(args, ++i, "--work-dir"));
                    case "--cache-dir" -> cacheDir = Path.of(requireArg(args, ++i, "--cache-dir"));
                    case "--no-cache" -> noCache = true;
                    case "--host" -> host = requireArg(args, ++i, "--host");
                    case "--port" -> port = Integer.parseInt(requireArg(args, ++i, "--port"));
                    case "--public-url" -> publicUrl = requireArg(args, ++i, "--public-url");
                    case "--cors-origin" -> corsOrigin = requireArg(args, ++i, "--cors-origin");
                    case "--decompiler-pool" -> poolSize = Integer.parseInt(requireArg(args, ++i, "--decompiler-pool"));
                    case "--rw-token" -> rwToken = requireArg(args, ++i, "--rw-token");
                    case "--ro-token" -> roToken = requireArg(args, ++i, "--ro-token");
                    default -> throw new IllegalArgumentException("Unknown argument: " + args[i]);
                }
            }
            if (workDir == null) {
                throw new IllegalArgumentException("--work-dir is required");
            }
            if (noCache) cacheDir = null;
            if (publicUrl != null) {
                publicUrl = publicUrl.strip();
                if (publicUrl.isEmpty()) {
                    publicUrl = null;
                } else {
                    URI url = URI.create(publicUrl);
                    if (!("http".equalsIgnoreCase(url.getScheme()) || "https".equalsIgnoreCase(url.getScheme()))
                            || url.getHost() == null || url.getRawUserInfo() != null
                            || url.getRawQuery() != null || url.getRawFragment() != null
                            || url.getPort() == 0 || url.getPort() > 65535) {
                        throw new IllegalArgumentException("--public-url must be an HTTP or HTTPS URL with a host");
                    }
                }
            }
            if (corsOrigin != null) {
                corsOrigin = corsOrigin.strip();
                if (corsOrigin.isEmpty()) corsOrigin = null;
            }
            if ("*".equals(corsOrigin)) throw new IllegalArgumentException("--cors-origin must name one viewer origin");
            if (rwToken != null && rwToken.isBlank() || roToken != null && roToken.isBlank()) {
                throw new IllegalArgumentException("Configured bearer tokens must be non-empty");
            }
            return new Config(binary, workDir, cacheDir, host, port, publicUrl, corsOrigin, poolSize, rwToken, roToken);
        }

        private static String requireArg(String[] args, int idx, String flag) {
            if (idx >= args.length) throw new IllegalArgumentException(flag + " requires a value");
            return args[idx];
        }
    }
}
