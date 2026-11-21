package org.esperware.ghidramcp;

import com.google.gson.Gson;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.Msg;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/** Headless Ghidra entry point hosting /mcp/rw, /mcp/ro, /api/v1/*, and the WebUI on one Jetty port. */
public final class GhidraMcpLauncher implements GhidraLaunchable {
    public GhidraMcpLauncher() {}

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        Config cfg = Config.parse(args);
        Path readyFile = cfg.workDir.resolve("ready.json");
        Files.createDirectories(cfg.workDir);
        Files.deleteIfExists(readyFile);

        ProxyServlet rwProxy = new ProxyServlet();
        ProxyServlet roProxy = new ProxyServlet();
        WebApiServlet webApi = new WebApiServlet(cfg.webuiDir, cfg.corsOrigin);

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

        if (cfg.rwToken != null || cfg.roToken != null) {
            ctx.addFilter(new FilterHolder(authFilter(cfg.rwToken, cfg.roToken)), "/*",
                    EnumSet.of(DispatcherType.REQUEST));
        }

        jetty.setHandler(ctx);
        jetty.setStopTimeout(1000);
        jetty.start();
        int boundPort = connector.getLocalPort();
        String advertisedHost = "0.0.0.0".equals(cfg.host) ? "127.0.0.1" : cfg.host;
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

            InspectService inspect = new InspectService(ws, store);
            EditService edit = new EditService(ws, store);
            McpEndpoints mcp = new McpEndpoints(inspect, edit, cfg.host, cfg.corsOrigin);
            mcpRef.set(mcp);

            rwProxy.attach(mcp.rwTransport());
            roProxy.attach(mcp.roTransport());
            webApi.markReady(new WebApiServlet.ReadyContext(
                    ws, store, inspect, baseUrl + "/mcp/rw", baseUrl + "/mcp/ro", shutdownTrigger));

            Map<String, Object> ready = new LinkedHashMap<>();
            ready.put("status", "ready");
            ready.put("pid", ProcessHandle.current().pid());
            ready.put("binary_name", ws.binaryName());
            ready.put("binary_sha256", ws.binarySha256());
            ready.put("current_version", store.currentVersion());
            ready.put("mcp_rw_url", baseUrl + "/mcp/rw");
            ready.put("mcp_ro_url", baseUrl + "/mcp/ro");
            ready.put("api_url", baseUrl + "/api/v1");
            ready.put("webui_url", baseUrl + "/");

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

    private static Filter authFilter(String rwToken, String roToken) {
        return (ServletRequest request, ServletResponse response, FilterChain chain) -> {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse resp = (HttpServletResponse) response;
            String path = req.getRequestURI();
            String required = null;
            boolean allowRwFallback = false;
            if ("/mcp/rw".equals(path) || ("/api/v1/shutdown".equals(path) && "POST".equalsIgnoreCase(req.getMethod()))) {
                required = rwToken;
            } else if ("/mcp/ro".equals(path)) {
                required = roToken;
                allowRwFallback = true;
            }
            if (required != null) {
                String auth = req.getHeader("Authorization");
                String token = (auth != null && auth.startsWith("Bearer ")) ? auth.substring(7) : null;
                boolean ok = required.equals(token) || (allowRwFallback && rwToken != null && rwToken.equals(token));
                if (!ok) {
                    resp.setStatus(401);
                    resp.setContentType("application/json");
                    resp.getWriter().write("{\"ok\":false,\"error\":\"Unauthorized\"}");
                    return;
                }
            }
            chain.doFilter(request, response);
        };
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
            Path webuiDir,
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
            Path webuiDir = detectWebUiDir(System.getenv("GHIDRA_MCP_WEBUI_DIR"));
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
                    case "--webui-dir" -> webuiDir = Path.of(requireArg(args, ++i, "--webui-dir"));
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
            return new Config(binary, workDir, cacheDir, host, port, publicUrl, webuiDir, corsOrigin, poolSize, rwToken, roToken);
        }

        private static String requireArg(String[] args, int idx, String flag) {
            if (idx >= args.length) throw new IllegalArgumentException(flag + " requires a value");
            return args[idx];
        }

        private static Path detectWebUiDir(String env) {
            if (env != null && !env.isBlank() && Files.isDirectory(Path.of(env))) return Path.of(env);
            Path sibling = Path.of("../wui");
            if (Files.isDirectory(sibling)) return sibling;
            Path local = Path.of("wui");
            if (Files.isDirectory(local)) return local;
            return null;
        }
    }
}
