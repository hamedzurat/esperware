package org.esperware.ghidramcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HypothesisEventStoreTest {
    @TempDir Path directory;

    @Test
    void withdrawalKeepsHistoryAndFlagsDependentEditsUntilIndependentSupport() throws Exception {
        Path db = directory.resolve("hypotheses.sqlite");
        String hypothesisId;
        try (HypothesisEventStore store = new HypothesisEventStore(db)) {
            Map<String, Object> created = store.recordHypothesisEvents("run-1", List.of(Map.of(
                    "type", "create", "claim", "parameter is a session token",
                    "function_address", "00401230", "symbol", "param_1",
                    "evidence", List.of(Map.of("observation", "caller returns token", "program_revision", 12)),
                    "provenance", Map.of("tool", "inspect_function"))), null).getFirst();
            hypothesisId = String.valueOf(created.get("hypothesis_id"));
            store.recordHypothesisEvents("run-1", List.of(Map.of("type", "update",
                    "hypothesis_id", hypothesisId, "status", "supported")), null);
            store.linkEdit("run-1", "e-1", List.of(hypothesisId));
            Map<?, ?> supported = (Map<?, ?>) ((List<?>) store.activeSnapshot("run-1", 12)
                    .get("hypotheses")).getFirst();
            assertEquals("supported", supported.get("status"));
            Map<?, ?> stale = (Map<?, ?>) ((List<?>) store.activeSnapshot("run-1", 13)
                    .get("hypotheses")).getFirst();
            assertTrue(Boolean.TRUE.equals(stale.get("evidence_stale")));
            store.recordHypothesisEvents("run-1", List.of(Map.of(
                    "type", "withdraw", "hypothesis_id", hypothesisId,
                    "reason", "another caller passes a refresh token")), null);

            Map<String, Object> snapshot = store.activeSnapshot("run-1", 13);
            assertTrue(((List<?>) snapshot.get("hypotheses")).isEmpty());
            List<?> review = (List<?>) snapshot.get("needs_review_edits");
            assertEquals(1, review.size());
            assertEquals("e-1", ((Map<?, ?>) review.getFirst()).get("edit_id"));
            assertEquals(4, store.history("run-1", hypothesisId).size());
        }

        try (HypothesisEventStore reopened = new HypothesisEventStore(db)) {
            reopened.recordHypothesisEvents("run-1", List.of(Map.of(
                    "type", "update", "hypothesis_id", hypothesisId,
                    "clears_edit_id", "e-1", "independent_evidence",
                    Map.of("observation", "the parameter carries different request values", "program_revision", 13))), null);
            Map<String, Object> snapshot = reopened.activeSnapshot("run-1", 13);
            assertTrue(((List<?>) snapshot.get("needs_review_edits")).isEmpty());
            reopened.recordHypothesisEvents("run-1", List.of(Map.of(
                    "type", "create", "claim", "parameter is a request value",
                    "function_address", "00401230", "symbol", "param_1",
                    "evidence", List.of(Map.of("observation", "conflicting callers", "program_revision", 13)),
                    "provenance", Map.of("tool", "inspect_function"))), null);
            assertTrue(((List<?>) reopened.activeSnapshot("run-1", 13).get("hypotheses")).size() > 0);
        }
    }
}
