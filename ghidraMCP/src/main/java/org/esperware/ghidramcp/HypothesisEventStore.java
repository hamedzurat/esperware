package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Internal persistence boundary for trusted harness hypothesis events. */
public final class HypothesisEventStore implements AutoCloseable {
    private static final Type MAP_TYPE = new TypeToken<Map<String, Object>>() {}.getType();
    private final Connection connection;
    private final Gson gson = new Gson();

    public HypothesisEventStore(Path path) throws Exception {
        path.toAbsolutePath().getParent().toFile().mkdirs();
        connection = DriverManager.getConnection("jdbc:sqlite:" + path.toAbsolutePath());
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("CREATE TABLE IF NOT EXISTS hypothesis_events (" +
                    "sequence INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, " +
                    "event_json TEXT NOT NULL, created_at TEXT NOT NULL)");
            statement.execute("CREATE INDEX IF NOT EXISTS hypothesis_events_run " +
                    "ON hypothesis_events(run_id, sequence)");
        }
    }

    /**
     * Appends only events accepted by the trusted harness. No MCP tool exposes this method.
     * The returned event maps contain generated IDs for newly created hypotheses.
     */
    public synchronized List<Map<String, Object>> recordHypothesisEvents(
            String runId, List<Map<String, Object>> events, String editId) throws Exception {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId is required");
        List<Map<String, Object>> accepted = new ArrayList<>();
        connection.setAutoCommit(false);
        try {
            for (Map<String, Object> input : events) {
                Map<String, Object> event = new LinkedHashMap<>(input);
                String type = text(event, "type");
                if (!List.of("create", "update", "withdraw", "flag").contains(type)) {
                    throw new IllegalArgumentException("Unsupported hypothesis event type: " + type);
                }
                if ("create".equals(type)) {
                    event.putIfAbsent("hypothesis_id", "h-" + UUID.randomUUID());
                    event.putIfAbsent("status", "uncertain");
                    if (!event.containsKey("claim") || !event.containsKey("evidence")
                            || !event.containsKey("provenance")
                            || (!event.containsKey("function_address") && !event.containsKey("symbol"))) {
                        throw new IllegalArgumentException("create requires claim, evidence, provenance, and a function or symbol link");
                    }
                    if (!List.of("uncertain", "supported").contains(event.get("status"))) {
                        throw new IllegalArgumentException("create status must be uncertain or supported");
                    }
                } else if (!event.containsKey("hypothesis_id")) {
                    throw new IllegalArgumentException(type + " requires hypothesis_id");
                }
                if ("update".equals(type) && event.containsKey("status")
                        && !List.of("uncertain", "supported").contains(event.get("status"))) {
                    throw new IllegalArgumentException("update status must be uncertain or supported; use withdraw to withdraw");
                }
                if ("withdraw".equals(type) && !nonBlank(event.get("reason"))) {
                    throw new IllegalArgumentException("withdraw requires a reason");
                }
                if ("flag".equals(type) && (!nonBlank(event.get("edit_id")) || !nonBlank(event.get("reason")))) {
                    throw new IllegalArgumentException("flag requires edit_id and reason");
                }
                if ("update".equals(type) && event.containsKey("clears_edit_id")
                        && !nonBlank(event.get("independent_evidence"))
                        && !nonBlank(event.get("explicit_correction"))) {
                    throw new IllegalArgumentException("clearing a flag requires independent evidence or an explicit correction");
                }
                if (editId != null && !editId.isBlank()) event.put("linked_edit_id", editId);
                append(runId, event);
                accepted.add(event);
                if ("withdraw".equals(type)) appendDependentFlags(runId, event);
                if ("update".equals(type) && event.containsKey("clears_edit_id")) {
                    append(runId, Map.of("type", "clear_flag", "hypothesis_id", event.get("hypothesis_id"),
                            "edit_id", event.get("clears_edit_id"), "reason",
                            event.getOrDefault("independent_evidence", event.get("explicit_correction"))));
                }
            }
            connection.commit();
            connection.setAutoCommit(true);
            return accepted;
        } catch (Exception failure) {
            connection.rollback();
            connection.setAutoCommit(true);
            throw failure;
        }
    }

    /** Adds an edit dependency after the MCP has returned its committed edit ID. */
    public synchronized void linkEdit(String runId, String editId, List<String> hypothesisIds)
            throws Exception {
        if (editId == null || editId.isBlank()) throw new IllegalArgumentException("editId is required");
        append(runId, Map.of("type", "edit_link", "edit_id", editId,
                "hypothesis_ids", List.copyOf(hypothesisIds)));
    }

    public synchronized Map<String, Object> activeSnapshot(String runId, long revision)
            throws Exception {
        Map<String, Map<String, Object>> current = currentHypotheses(runId);
        List<Map<String, Object>> active = new ArrayList<>();
        Map<String, Map<String, Object>> flaggedEdits = new LinkedHashMap<>();
        for (Map<String, Object> event : readEvents(runId)) {
            String type = String.valueOf(event.get("type"));
            if ("flag".equals(type) && event.get("edit_id") != null) {
                flaggedEdits.put(String.valueOf(event.get("edit_id")), new LinkedHashMap<>(event));
            } else if ("clear_flag".equals(type) && event.get("edit_id") != null) {
                flaggedEdits.remove(String.valueOf(event.get("edit_id")));
            }
        }
        for (Map<String, Object> hypothesis : current.values()) {
            if ("withdrawn".equals(hypothesis.get("status"))) continue;
            Map<String, Object> snapshot = new LinkedHashMap<>(hypothesis);
            snapshot.put("evidence_stale", isEvidenceStale(snapshot, revision));
            active.add(snapshot);
        }
        return Map.of("hypotheses", active, "needs_review_edits", new ArrayList<>(flaggedEdits.values()));
    }

    public synchronized List<Map<String, Object>> history(String runId, String hypothesisId)
            throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        try (PreparedStatement query = connection.prepareStatement(
                "SELECT event_json FROM hypothesis_events WHERE run_id=? ORDER BY sequence")) {
            query.setString(1, runId);
            try (ResultSet rows = query.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> event = gson.fromJson(rows.getString(1), MAP_TYPE);
                    if (hypothesisId.equals(event.get("hypothesis_id"))) result.add(event);
                }
            }
        }
        return result;
    }

    private Map<String, Map<String, Object>> currentHypotheses(String runId) throws Exception {
        Map<String, Map<String, Object>> result = new LinkedHashMap<>();
        for (Map<String, Object> event : readEvents(runId)) {
            String type = String.valueOf(event.get("type"));
            String id = (String) event.get("hypothesis_id");
            if (id == null) continue;
            Map<String, Object> previous = result.get(id);
            if ("create".equals(type)) result.put(id, new LinkedHashMap<>(event));
            else if (previous != null && "update".equals(type)) {
                for (Map.Entry<String, Object> field : event.entrySet()) {
                    if (!List.of("type", "hypothesis_id", "clears_edit_id", "independent_evidence", "explicit_correction").contains(field.getKey())) {
                        previous.put(field.getKey(), field.getValue());
                    }
                }
            }
            else if (previous != null && "withdraw".equals(type)) {
                previous.put("status", "withdrawn");
                previous.put("withdrawal_reason", event.get("reason"));
            }
        }
        return result;
    }

    private List<Map<String, Object>> readEvents(String runId) throws Exception {
        List<Map<String, Object>> events = new ArrayList<>();
        try (PreparedStatement query = connection.prepareStatement(
                "SELECT event_json FROM hypothesis_events WHERE run_id=? ORDER BY sequence")) {
            query.setString(1, runId);
            try (ResultSet rows = query.executeQuery()) {
                while (rows.next()) events.add(gson.fromJson(rows.getString(1), MAP_TYPE));
            }
        }
        return events;
    }

    private void appendDependentFlags(String runId, Map<String, Object> withdrawn) throws Exception {
        String hypothesisId = String.valueOf(withdrawn.get("hypothesis_id"));
        for (Map<String, Object> event : readEvents(runId)) {
            Object ids = event.get("hypothesis_ids");
            if ("edit_link".equals(event.get("type")) && ids instanceof List<?> list && list.contains(hypothesisId)) {
                append(runId, Map.of("type", "flag", "hypothesis_id", hypothesisId,
                        "edit_id", event.get("edit_id"), "reason", "supporting hypothesis withdrawn"));
            }
        }
    }

    private boolean isEvidenceStale(Map<String, Object> hypothesis, long revision) {
        Object evidence = hypothesis.get("evidence");
        if (!(evidence instanceof List<?> list)) return false;
        for (Object item : list) {
            if (item instanceof Map<?, ?> map && map.get("program_revision") instanceof Number n
                    && n.longValue() < revision) return true;
        }
        return false;
    }

    private void append(String runId, Map<String, Object> event) throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "INSERT INTO hypothesis_events(run_id,event_json,created_at) VALUES(?,?,?)")) {
            insert.setString(1, runId);
            insert.setString(2, gson.toJson(event));
            insert.setString(3, Instant.now().toString());
            insert.executeUpdate();
        }
    }

    private static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(key + " is required");
        }
        return text;
    }

    private static boolean nonBlank(Object value) {
        return value instanceof String text && !text.isBlank() || value instanceof Map<?, ?> || value instanceof List<?>;
    }

    @Override public synchronized void close() throws Exception { connection.close(); }
}
