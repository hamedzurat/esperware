package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/** Linear SQLite-backed version ledger storing every mutation step, inverse ops, and pseudocode diffs. */
final class VersionStore implements AutoCloseable {
    private static final String PENDING_VERSION = "pending_version";
    private static final String REVERSIBLE_TYPES_FROM = "reversible_types_from";
    private static final Type MAP_LIST_TYPE = new TypeToken<List<Map<String, Object>>>() {}.getType();

    record FunctionDiff(
            String functionAddress,
            String functionName,
            String beforeC,
            String afterC,
            String diff,
            String decompileStatus) {}

    record SseEvent(String type, Map<String, Object> data) {}

    @FunctionalInterface
    interface ProjectSave {
        void save(long version) throws Exception;
    }

    private final Connection db;
    private final Gson gson = new Gson();
    private final CopyOnWriteArrayList<Consumer<SseEvent>> listeners = new CopyOnWriteArrayList<>();
    private long currentVersion;
    private long reversibleTypesFrom;

    VersionStore(Path dbFile) throws Exception {
        Path abs = dbFile.toAbsolutePath();
        if (abs.getParent() != null) Files.createDirectories(abs.getParent());
        db = DriverManager.getConnection("jdbc:sqlite:" + abs);
        try (Statement s = db.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL");
            s.execute("PRAGMA synchronous=FULL");
            s.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
            s.execute("CREATE TABLE IF NOT EXISTS versions ("
                    + "version INTEGER PRIMARY KEY, "
                    + "parent_version INTEGER, "
                    + "created_at TEXT NOT NULL, "
                    + "actor TEXT NOT NULL, "
                    + "operation TEXT NOT NULL, "
                    + "reason TEXT, "
                    + "checkpoint_label TEXT, "
                    + "ops_json TEXT, "
                    + "inverse_ops_json TEXT, "
                    + "functions_json TEXT)");
            s.execute("CREATE TABLE IF NOT EXISTS function_diffs ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "version INTEGER NOT NULL, "
                    + "function_address TEXT NOT NULL, "
                    + "function_name TEXT NOT NULL, "
                    + "before_c TEXT, "
                    + "after_c TEXT, "
                    + "diff_text TEXT NOT NULL, "
                    + "decompile_status TEXT NOT NULL)");
            s.execute("CREATE INDEX IF NOT EXISTS idx_fdiffs_ver_addr ON function_diffs(version, function_address)");
        }
        currentVersion = queryMaxVersion();
    }

    synchronized void ensureBaseline(Map<String, String> meta) throws SQLException {
        long count;
        try (Statement s = db.createStatement(); ResultSet r = s.executeQuery("SELECT COUNT(*) FROM versions")) {
            count = r.next() ? r.getLong(1) : 0L;
        }
        if (count == 0L) {
            db.setAutoCommit(false);
            try {
                try (PreparedStatement ps = db.prepareStatement("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)")) {
                    for (Map.Entry<String, String> e : meta.entrySet()) {
                        if (e.getValue() == null) continue;
                        ps.setString(1, e.getKey());
                        ps.setString(2, e.getValue());
                        ps.addBatch();
                    }
                    ps.executeBatch();
                }
                try (PreparedStatement ps = db.prepareStatement(
                        "INSERT INTO versions(version, parent_version, created_at, actor, operation, reason, checkpoint_label, ops_json, inverse_ops_json, functions_json) "
                                + "VALUES (0, NULL, ?, 'system', 'initial', 'baseline', NULL, '[]', '[]', '[]')")) {
                    ps.setString(1, Instant.now().toString());
                    ps.executeUpdate();
                }
                db.commit();
                currentVersion = 0L;
            } catch (SQLException ex) {
                db.rollback();
                throw ex;
            } finally {
                db.setAutoCommit(true);
            }
        } else {
            String savedHash = metadata().get("binary_sha256");
            String hash = meta.get("binary_sha256");
            if (!(hash == null ? savedHash == null : hash.equalsIgnoreCase(savedHash))) {
                throw new SQLException("History belongs to a different binary");
            }
        }
    }

    synchronized void recover(long savedVersion, ProjectSave saveProject) throws Exception {
        Map<String, String> meta = metadata();
        String pending = meta.get(PENDING_VERSION);
        long latest = queryMaxVersion();
        if (pending != null) {
            long version = Long.parseLong(pending);
            if (version != latest || version <= 0 || (savedVersion != version && savedVersion != version - 1)) {
                throw new SQLException("Pending history version does not match the saved project");
            }
            finishPending(version, savedVersion == version);
            latest = savedVersion;
        } else if (savedVersion != ProgramWorkspace.UNTRACKED_VERSION && savedVersion != latest) {
            throw new SQLException("Saved project version does not match history");
        }

        String firstReversible = meta.get(REVERSIBLE_TYPES_FROM);
        if (firstReversible == null) {
            reversibleTypesFrom = latest + 1;
            putMetadata(REVERSIBLE_TYPES_FROM, Long.toString(reversibleTypesFrom));
        } else {
            reversibleTypesFrom = Long.parseLong(firstReversible);
            if (savedVersion == ProgramWorkspace.UNTRACKED_VERSION && latest >= reversibleTypesFrom) {
                throw new SQLException("Saved project is missing its history version");
            }
        }
        if (savedVersion == ProgramWorkspace.UNTRACKED_VERSION) saveProject.save(latest);
        currentVersion = latest;
    }

    private void putMetadata(String key, String value) throws SQLException {
        try (PreparedStatement ps = db.prepareStatement("INSERT INTO meta(key, value) VALUES (?, ?)")) {
            ps.setString(1, key);
            ps.setString(2, value);
            ps.executeUpdate();
        }
    }

    private void finishPending(long version, boolean keep) throws SQLException {
        db.setAutoCommit(false);
        try (Statement s = db.createStatement()) {
            if (!keep) {
                s.executeUpdate("DELETE FROM function_diffs WHERE version = " + version);
                s.executeUpdate("DELETE FROM versions WHERE version = " + version);
            }
            s.executeUpdate("DELETE FROM meta WHERE key = 'pending_version'");
            db.commit();
        } catch (SQLException e) {
            db.rollback();
            throw e;
        } finally {
            db.setAutoCommit(true);
        }
    }

    synchronized long currentVersion() {
        return currentVersion;
    }

    synchronized Map<String, String> metadata() throws SQLException {
        Map<String, String> out = new LinkedHashMap<>();
        try (Statement s = db.createStatement(); ResultSet r = s.executeQuery("SELECT key, value FROM meta ORDER BY key")) {
            while (r.next()) out.put(r.getString(1), r.getString(2));
        }
        return out;
    }

    long recordVersion(
            String actor,
            String operation,
            String reason,
            Object ops,
            Object inverseOps,
            List<FunctionDiff> diffs,
            ProjectSave saveProject) throws Exception {
        long newVer;
        List<Map<String, Object>> fnSummary = new ArrayList<>(diffs.size());
        for (FunctionDiff d : diffs) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("function_address", d.functionAddress());
            item.put("function_name", d.functionName());
            item.put("decompile_status", d.decompileStatus());
            fnSummary.add(item);
        }
        String now = Instant.now().toString();
        String opsJson = gson.toJson(ops == null ? List.of() : ops);
        String inverseJson = gson.toJson(inverseOps == null ? List.of() : inverseOps);
        String functionsJson = gson.toJson(fnSummary);
        synchronized (this) {
            long parent = currentVersion;
            newVer = parent + 1;
            db.setAutoCommit(false);
            try {
                try (PreparedStatement ps = db.prepareStatement(
                        "INSERT INTO versions(version, parent_version, created_at, actor, operation, reason, ops_json, inverse_ops_json, functions_json) "
                                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                    ps.setLong(1, newVer);
                    ps.setLong(2, parent);
                    ps.setString(3, now);
                    ps.setString(4, actor == null ? "agent" : actor);
                    ps.setString(5, operation);
                    if (reason == null) ps.setNull(6, Types.VARCHAR);
                    else ps.setString(6, reason);
                    ps.setString(7, opsJson);
                    ps.setString(8, inverseJson);
                    ps.setString(9, functionsJson);
                    ps.executeUpdate();
                }
                if (!diffs.isEmpty()) {
                    try (PreparedStatement ps = db.prepareStatement(
                            "INSERT INTO function_diffs(version, function_address, function_name, before_c, after_c, diff_text, decompile_status) "
                                    + "VALUES (?, ?, ?, ?, ?, ?, ?)")) {
                        for (FunctionDiff d : diffs) {
                            ps.setLong(1, newVer);
                            ps.setString(2, d.functionAddress());
                            ps.setString(3, d.functionName());
                            if (d.beforeC() == null) ps.setNull(4, Types.VARCHAR);
                            else ps.setString(4, d.beforeC());
                            if (d.afterC() == null) ps.setNull(5, Types.VARCHAR);
                            else ps.setString(5, d.afterC());
                            ps.setString(6, d.diff() == null ? "" : d.diff());
                            ps.setString(7, d.decompileStatus());
                            ps.addBatch();
                        }
                        ps.executeBatch();
                    }
                }
                putMetadata(PENDING_VERSION, Long.toString(newVer));
                db.commit();
            } catch (SQLException | RuntimeException ex) {
                db.rollback();
                throw ex;
            } finally {
                db.setAutoCommit(true);
            }
            saveProject.save(newVer);
            finishPending(newVer, true);
            currentVersion = newVer;
        }
        Map<String, Object> evt = new LinkedHashMap<>();
        evt.put("version", newVer);
        evt.put("parent_version", newVer - 1);
        evt.put("created_at", now);
        evt.put("actor", actor == null ? "agent" : actor);
        evt.put("operation", operation);
        evt.put("reason", reason);
        evt.put("functions", fnSummary);
        emit("version_created", evt);
        return newVer;
    }

    void tagCheckpoint(long version, String label) throws SQLException {
        String cleanLabel = (label == null || label.isBlank()) ? "checkpoint-v" + version : label.trim();
        synchronized (this) {
            try (PreparedStatement ps = db.prepareStatement("UPDATE versions SET checkpoint_label = ? WHERE version = ?")) {
                ps.setString(1, cleanLabel);
                ps.setLong(2, version);
                int updated = ps.executeUpdate();
                if (updated == 0) {
                    throw new ApiError("NOT_FOUND", "Unknown version " + version, currentVersion);
                }
            }
        }
        emit("checkpoint_saved", Map.of("version", version, "checkpoint_label", cleanLabel));
    }

    synchronized List<Map<String, Object>> listVersions() throws SQLException {
        List<Map<String, Object>> out = new ArrayList<>();
        String sql = "SELECT version, parent_version, created_at, actor, operation, reason, checkpoint_label, ops_json, functions_json "
                + "FROM versions WHERE version <= ? ORDER BY version ASC";
        try (PreparedStatement ps = db.prepareStatement(sql)) {
            ps.setLong(1, currentVersion);
            try (ResultSet r = ps.executeQuery()) {
                while (r.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("version", r.getLong("version"));
                    long parent = r.getLong("parent_version");
                    row.put("parent_version", r.wasNull() ? null : parent);
                    row.put("created_at", r.getString("created_at"));
                    row.put("actor", r.getString("actor"));
                    row.put("operation", r.getString("operation"));
                    row.put("reason", r.getString("reason"));
                    row.put("checkpoint_label", r.getString("checkpoint_label"));
                    List<Map<String, Object>> ops = parseMapList(r.getString("ops_json"));
                    row.put("ops_count", ops.size());
                    row.put("functions", parseMapList(r.getString("functions_json")));
                    out.add(row);
                }
            }
        }
        return out;
    }

    synchronized Map<String, Object> getVersion(long version) throws SQLException {
        if (version > currentVersion) return null;
        Map<String, Object> out = null;
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT version, parent_version, created_at, actor, operation, reason, checkpoint_label, ops_json "
                        + "FROM versions WHERE version = ?")) {
            ps.setLong(1, version);
            try (ResultSet r = ps.executeQuery()) {
                if (!r.next()) return null;
                out = new LinkedHashMap<>();
                out.put("version", r.getLong("version"));
                long parent = r.getLong("parent_version");
                out.put("parent_version", r.wasNull() ? null : parent);
                out.put("created_at", r.getString("created_at"));
                out.put("actor", r.getString("actor"));
                out.put("operation", r.getString("operation"));
                out.put("reason", r.getString("reason"));
                out.put("checkpoint_label", r.getString("checkpoint_label"));
                out.put("ops", parseMapList(r.getString("ops_json")));
            }
        }
        List<Map<String, Object>> diffs = new ArrayList<>();
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT function_address, function_name, before_c, after_c, diff_text, decompile_status "
                        + "FROM function_diffs WHERE version = ? ORDER BY id ASC")) {
            ps.setLong(1, version);
            try (ResultSet r = ps.executeQuery()) {
                while (r.next()) {
                    Map<String, Object> d = new LinkedHashMap<>();
                    d.put("function_address", r.getString("function_address"));
                    d.put("function_name", r.getString("function_name"));
                    d.put("before_c", r.getString("before_c"));
                    d.put("after_c", r.getString("after_c"));
                    d.put("diff", r.getString("diff_text"));
                    d.put("decompile_status", r.getString("decompile_status"));
                    diffs.add(d);
                }
            }
        }
        out.put("diffs", diffs);
        return out;
    }

    synchronized List<Map<String, Object>> inverseOpsRange(long fromExclusive, long toInclusive) throws SQLException {
        List<Map<String, Object>> result = new ArrayList<>();
        try (PreparedStatement ps = db.prepareStatement(
                "SELECT version, operation, ops_json, inverse_ops_json FROM versions "
                        + "WHERE version > ? AND version <= ? ORDER BY version DESC")) {
            ps.setLong(1, fromExclusive);
            ps.setLong(2, toInclusive);
            try (ResultSet r = ps.executeQuery()) {
                while (r.next()) {
                    long version = r.getLong("version");
                    boolean legacyType = "define_type".equals(r.getString("operation")) && version < reversibleTypesFrom;
                    boolean destructive = parseMapList(r.getString("ops_json")).stream().anyMatch(op ->
                            "remove_type".equals(op.get("op")) || "delete_function".equals(op.get("op")));
                    List<Map<String, Object>> inverses = parseMapList(r.getString("inverse_ops_json"));
                    if (legacyType || destructive || inverses.isEmpty()) {
                        throw new ApiError("REVERT_UNAVAILABLE", "History version " + version
                                + " cannot be fully reversed", currentVersion);
                    }
                    result.addAll(inverses);
                }
            }
        }
        return result;
    }

    synchronized Map<String, Object> diffRange(long fromVersion, long toVersion, String functionFilter) throws SQLException {
        if (fromVersion < 0 || toVersion < fromVersion || toVersion > currentVersion) {
            throw new ApiError("INVALID_ARGUMENT",
                    "Invalid version range " + fromVersion + ".." + toVersion + " (current=" + currentVersion + ")",
                    currentVersion);
        }
        String sql = "SELECT function_address, function_name, before_c, after_c, decompile_status "
                + "FROM function_diffs WHERE version > ? AND version <= ? "
                + (functionFilter != null ? """
                      AND function_address IN (
                          SELECT function_address FROM function_diffs
                          WHERE version > ? AND version <= ?
                            AND (LOWER(function_address) = LOWER(?) OR LOWER(function_name) = LOWER(?))
                      )
                      """ : "")
                + "ORDER BY version ASC, id ASC";
        Map<String, RangeAcc> byAddr = new LinkedHashMap<>();
        try (PreparedStatement ps = db.prepareStatement(sql)) {
            int i = 1;
            ps.setLong(i++, fromVersion);
            ps.setLong(i++, toVersion);
            if (functionFilter != null) {
                String clean = functionFilter.startsWith("0x") || functionFilter.startsWith("0X")
                        ? functionFilter.substring(2) : functionFilter;
                ps.setLong(i++, fromVersion);
                ps.setLong(i++, toVersion);
                ps.setString(i++, clean);
                ps.setString(i, functionFilter);
            }
            try (ResultSet r = ps.executeQuery()) {
                while (r.next()) {
                    String addr = r.getString("function_address");
                    RangeAcc acc = byAddr.computeIfAbsent(addr, k -> new RangeAcc(addr));
                    String before = r.getString("before_c");
                    String after = r.getString("after_c");
                    if (!acc.seenBefore && before != null) {
                        acc.firstBefore = before;
                        acc.seenBefore = true;
                    }
                    if (after != null) acc.lastAfter = after;
                    acc.latestName = r.getString("function_name");
                    acc.latestStatus = r.getString("decompile_status");
                }
            }
        }
        List<Map<String, Object>> diffs = new ArrayList<>(byAddr.size());
        for (RangeAcc acc : byAddr.values()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("function_address", acc.address);
            entry.put("function_name", acc.latestName);
            entry.put("decompile_status", acc.latestStatus);
            entry.put("before_c", acc.firstBefore);
            entry.put("after_c", acc.lastAfter);
            entry.put("diff", ApiError.unifiedDiff(acc.latestName + " @ " + acc.address, acc.firstBefore, acc.lastAfter));
            diffs.add(entry);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("from", fromVersion);
        out.put("to", toVersion);
        out.put("diffs", diffs);
        return out;
    }

    AutoCloseable subscribe(Consumer<SseEvent> listener) {
        listeners.add(listener);
        return () -> listeners.remove(listener);
    }

    void emit(String type, Map<String, Object> data) {
        SseEvent evt = new SseEvent(type, data);
        for (Consumer<SseEvent> l : listeners) {
            try {
                l.accept(evt);
            } catch (Exception ignored) {
                // Listener handles removal on broken pipe
            }
        }
    }

    private long queryMaxVersion() throws SQLException {
        try (Statement s = db.createStatement(); ResultSet r = s.executeQuery("SELECT COALESCE(MAX(version), 0) FROM versions")) {
            return r.next() ? r.getLong(1) : 0L;
        }
    }

    private List<Map<String, Object>> parseMapList(String json) {
        if (json == null || json.isBlank()) return List.of();
        List<Map<String, Object>> parsed = gson.fromJson(json, MAP_LIST_TYPE);
        return parsed == null ? List.of() : parsed;
    }

    @Override
    public synchronized void close() throws Exception {
        listeners.clear();
        db.close();
    }

    private static final class RangeAcc {
        final String address;
        boolean seenBefore;
        String firstBefore;
        String lastAfter;
        String latestName;
        String latestStatus;

        RangeAcc(String address) {
            this.address = address;
        }
    }
}
