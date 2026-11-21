package org.esperware.ghidramcp;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VersionStoreTest {
    @TempDir Path dir;

    @Test
    void tracksLinearVersionsDiffsCheckpointsAndInverseOpsAcrossReopen() throws Exception {
        Path db = dir.resolve("history.sqlite");
        Map<String, String> meta = Map.of(
                "binary_name", "sample.elf",
                "binary_sha256", "deadbeef",
                "ghidra_version", "12.2",
                "arch", "x86:LE:64");

        try (VersionStore store = new VersionStore(db)) {
            store.ensureBaseline(meta);
            // Calling ensureBaseline twice is idempotent
            store.ensureBaseline(meta);
            assertEquals(0L, store.currentVersion());
            assertEquals("sample.elf", store.metadata().get("binary_name"));

            long v1 = store.recordVersion(
                    "rw-agent",
                    "apply_edits",
                    "rename transform",
                    List.of(Map.of("op", "rename_function", "target", "0x40116d", "new_name", "transform")),
                    List.of(Map.of("op", "rename_function", "target", "0x40116d", "new_name", "FUN_0040116d")),
                    List.of(new VersionStore.FunctionDiff(
                            "0040116d",
                            "transform",
                            "void FUN_0040116d(void) {\n  return;\n}\n",
                            "void transform(void) {\n  return;\n}\n",
                            ApiError.unifiedDiff("FUN_0040116d", "void FUN_0040116d(void) {\n  return;\n}\n",
                                    "void transform(void) {\n  return;\n}\n"),
                            "complete")));
            assertEquals(1L, v1);

            long v2 = store.recordVersion(
                    "rw-agent",
                    "apply_edits",
                    "add function comment",
                    List.of(Map.of("op", "set_comment", "target", "0040116d", "text", "mix helper")),
                    List.of(Map.of("op", "set_comment", "target", "0040116d", "text", "")),
                    List.of(new VersionStore.FunctionDiff(
                            "0040116d",
                            "transform",
                            "void transform(void) {\n  return;\n}\n",
                            "/* mix helper */\nvoid transform(void) {\n  return;\n}\n",
                            ApiError.unifiedDiff("transform", "void transform(void) {\n  return;\n}\n",
                                    "/* mix helper */\nvoid transform(void) {\n  return;\n}\n"),
                            "complete")));
            assertEquals(2L, v2);

            store.tagCheckpoint(v2, "first-pass");

            // listVersions stays lightweight (omits raw before_c/after_c blobs)
            var list = store.listVersions();
            assertEquals(3, list.size());
            assertEquals(0L, list.get(0).get("version"));
            assertEquals("initial", list.get(0).get("operation"));
            assertEquals("first-pass", list.get(2).get("checkpoint_label"));
            assertFalse(list.get(2).containsKey("before_c"));
            assertFalse(list.get(2).containsKey("after_c"));

            // getVersion includes full diffs
            var detail = store.getVersion(1L);
            assertNotNull(detail);
            assertEquals("rename transform", detail.get("reason"));
            @SuppressWarnings("unchecked")
            var diffs = (List<Map<String, Object>>) detail.get("diffs");
            assertEquals(1, diffs.size());
            assertTrue(String.valueOf(diffs.get(0).get("diff")).contains("-void FUN_0040116d"));
            assertTrue(String.valueOf(diffs.get(0).get("diff")).contains("+void transform"));

            // Cross-stage diff from v0 to v2 captures earliest before_c -> latest after_c
            var range = store.diffRange(0L, 2L, null);
            @SuppressWarnings("unchecked")
            var rangeDiffs = (List<Map<String, Object>>) range.get("diffs");
            assertEquals(1, rangeDiffs.size());
            String cumulative = String.valueOf(rangeDiffs.get(0).get("diff"));
            assertTrue(cumulative.contains("-void FUN_0040116d"));
            assertTrue(cumulative.contains("+/* mix helper */"));
            assertTrue(cumulative.contains("+void transform"));

            // inverseOpsRange returns v2 inverse ops BEFORE v1 inverse ops
            var inverses = store.inverseOpsRange(0L, 2L);
            assertEquals(2, inverses.size());
            assertEquals("set_comment", inverses.get(0).get("op"));
            assertEquals("rename_function", inverses.get(1).get("op"));
        }

        // Persistence across restart
        try (VersionStore reopened = new VersionStore(db)) {
            reopened.ensureBaseline(meta);
            assertEquals(2L, reopened.currentVersion());
            assertEquals(3, reopened.listVersions().size());
            assertNull(reopened.getVersion(99L));
        }
    }
}
