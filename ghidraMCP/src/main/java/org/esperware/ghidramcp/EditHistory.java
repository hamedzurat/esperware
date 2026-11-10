package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Durable, read-only HTTP view of committed MCP edits. */
final class EditHistory implements AutoCloseable {
    private final Connection db;
    private final HttpServer server;
    private final Gson gson = new Gson();

    EditHistory(Path file, String host, int port) throws Exception {
        Files.createDirectories(file.toAbsolutePath().getParent());
        db = DriverManager.getConnection("jdbc:sqlite:" + file.toAbsolutePath());
        try (var s = db.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL");
            s.execute("CREATE TABLE IF NOT EXISTS edits (id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "created_at TEXT NOT NULL, project TEXT NOT NULL, program TEXT NOT NULL, " +
                    "session_id TEXT NOT NULL, generation INTEGER NOT NULL, revision INTEGER NOT NULL, " +
                    "operation TEXT NOT NULL, edit_id TEXT NOT NULL, function_address TEXT NOT NULL, " +
                    "target_json TEXT, change_json TEXT, before_status TEXT NOT NULL, before_code TEXT, " +
                    "after_status TEXT NOT NULL, after_code TEXT, after_error TEXT)");
            s.execute("CREATE INDEX IF NOT EXISTS edits_program ON edits(project, program, function_address, id)");
        }
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.createContext("/api/v1/edits", this::handle);
        server.start();
    }

    synchronized void append(String project, String program, String session, long generation,
            long revision, String operation, String editId, String address, Object target, Object change,
            Map<String, Object> before, Map<String, Object> after) throws SQLException {
        try (PreparedStatement s = db.prepareStatement("INSERT INTO edits " +
                "(created_at,project,program,session_id,generation,revision,operation,edit_id,function_address," +
                "target_json,change_json,before_status,before_code,after_status,after_code,after_error) " +
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
            s.setString(1, Instant.now().toString()); s.setString(2, project); s.setString(3, program);
            s.setString(4, session); s.setLong(5, generation); s.setLong(6, revision);
            s.setString(7, operation); s.setString(8, editId); s.setString(9, address);
            s.setString(10, target == null ? null : gson.toJson(target));
            s.setString(11, change == null ? null : gson.toJson(change));
            s.setString(12, String.valueOf(before.get("status"))); s.setString(13, (String) before.get("code"));
            s.setString(14, String.valueOf(after.get("status"))); s.setString(15, (String) after.get("code"));
            s.setString(16, (String) after.get("error")); s.executeUpdate();
        }
    }

    int port() { return server.getAddress().getPort(); }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            if (!exchange.getRequestMethod().equals("GET")) { respond(exchange, 405, Map.of("error", "GET required")); return; }
            String path = exchange.getRequestURI().getPath();
            String base = "/api/v1/edits";
            if (!path.equals(base) && !path.matches(base + "/[0-9]+")) { respond(exchange, 404, Map.of("error", "not found")); return; }
            Map<String, String> params = new LinkedHashMap<>();
            String query = exchange.getRequestURI().getRawQuery();
            if (query != null) for (String pair : query.split("&")) {
                String[] parts = pair.split("=", 2);
                params.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), URLDecoder.decode(parts.length > 1 ? parts[1] : "", StandardCharsets.UTF_8));
            }
            long after = Long.parseLong(params.getOrDefault("after", "0"));
            int limit = Integer.parseInt(params.getOrDefault("limit", "50"));
            if (after < 0 || limit < 1 || limit > 100) throw new IllegalArgumentException();
            Long id = path.equals(base) ? null : Long.parseLong(path.substring(base.length() + 1));
            List<Map<String, Object>> rows = list(id, after, limit, params.get("project"), params.get("program"), params.get("function_address"));
            if (id != null && rows.isEmpty()) { respond(exchange, 404, Map.of("error", "not found")); return; }
            respond(exchange, 200, id == null ? Map.of("edits", rows, "next_after", rows.isEmpty() ? after : rows.getLast().get("id")) : rows.getFirst());
        } catch (IllegalArgumentException e) { respond(exchange, 400, Map.of("error", "invalid query")); }
        catch (SQLException e) { respond(exchange, 500, Map.of("error", "history unavailable")); }
        finally { exchange.close(); }
    }

    private synchronized List<Map<String, Object>> list(Long id, long after, int limit, String project, String program, String address) throws SQLException {
        String sql = "SELECT * FROM edits WHERE id > ?" + (id == null ? "" : " AND id = ?") +
                (project == null ? "" : " AND project = ?") + (program == null ? "" : " AND program = ?") +
                (address == null ? "" : " AND function_address = ?") + " ORDER BY id LIMIT ?";
        List<Map<String, Object>> rows = new ArrayList<>();
        try (PreparedStatement s = db.prepareStatement(sql)) {
            int i = 1; s.setLong(i++, id == null ? after : 0); if (id != null) s.setLong(i++, id);
            if (project != null) s.setString(i++, project); if (program != null) s.setString(i++, program);
            if (address != null) s.setString(i++, address); s.setInt(i, limit);
            try (ResultSet r = s.executeQuery()) {
                while (r.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (String key : List.of("id", "created_at", "project", "program", "session_id", "generation", "revision", "operation", "edit_id", "function_address", "before_status", "before_code", "after_status", "after_code", "after_error")) row.put(key, r.getObject(key));
                    for (String key : List.of("target", "change")) { String json = r.getString(key + "_json"); row.put(key, json == null ? null : gson.fromJson(json, Object.class)); }
                    rows.add(row);
                }
            }
        }
        return rows;
    }

    private void respond(HttpExchange e, int status, Object body) throws IOException {
        byte[] bytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        e.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        e.getResponseHeaders().set("Cache-Control", "no-store");
        e.sendResponseHeaders(status, bytes.length); e.getResponseBody().write(bytes);
    }
    @Override public synchronized void close() throws Exception { server.stop(0); db.close(); }
}
