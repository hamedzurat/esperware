package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Shared error type, access mode, argument validation, cursor helpers, and unified diff utility. */
final class ApiError extends RuntimeException {
    final String code;
    final Long currentVersion;

    ApiError(String code, String message, Long currentVersion) {
        super(message);
        this.code = code;
        this.currentVersion = currentVersion;
    }

    enum AccessMode {
        READ_ONLY,
        READ_WRITE
    }

    static String reqStr(Map<String, Object> args, String key) {
        Object val = args == null ? null : args.get(key);
        if (!(val instanceof String s) || s.isBlank()) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be a non-empty string", null);
        }
        return s.trim();
    }

    static String reqRawStr(Map<String, Object> args, String key) {
        Object val = args == null ? null : args.get(key);
        if (!(val instanceof String s)) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be a string", null);
        }
        return s;
    }

    static String optStr(Map<String, Object> args, String key) {
        Object val = args == null ? null : args.get(key);
        if (val == null) return null;
        if (!(val instanceof String s)) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be a string", null);
        }
        return s.isBlank() ? null : s.trim();
    }

    static long reqLong(Map<String, Object> args, String key, Long currentVersion) {
        Object val = args == null ? null : args.get(key);
        if (!(val instanceof Number n)) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be an integer", currentVersion);
        }
        return n.longValue();
    }

    static int optInt(Map<String, Object> args, String key, int defaultVal, int min, int max) {
        Object val = args == null ? null : args.get(key);
        if (val == null) return defaultVal;
        if (!(val instanceof Number n)) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be an integer", null);
        }
        int v = n.intValue();
        if (v < min || v > max) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be between " + min + " and " + max, null);
        }
        return v;
    }

    static boolean optBool(Map<String, Object> args, String key, boolean defaultVal) {
        Object val = args == null ? null : args.get(key);
        if (val == null) return defaultVal;
        if (!(val instanceof Boolean b)) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be a boolean", null);
        }
        return b;
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> reqMapList(Map<String, Object> args, String key, int maxItems) {
        Object val = args == null ? null : args.get(key);
        if (!(val instanceof List<?> raw) || raw.isEmpty()) {
            throw new ApiError("INVALID_ARGUMENT", key + " must be a non-empty array", null);
        }
        if (raw.size() > maxItems) {
            throw new ApiError("INVALID_ARGUMENT", key + " exceeds max " + maxItems + " items", null);
        }
        List<Map<String, Object>> out = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?> m)) {
                throw new ApiError("INVALID_ARGUMENT", key + " items must be objects", null);
            }
            out.add((Map<String, Object>) m);
        }
        return out;
    }

    static String encodeCursor(Gson gson, Object payload) {
        byte[] bytes = gson.toJson(payload).getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static <T> T decodeCursor(Gson gson, Object raw, Class<T> type) {
        if (raw == null) return null;
        if (!(raw instanceof String s) || s.isBlank()) {
            throw new ApiError("INVALID_CURSOR", "cursor must be a non-empty string", null);
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(s);
            T parsed = gson.fromJson(new String(decoded, StandardCharsets.UTF_8), type);
            if (parsed == null) throw new ApiError("INVALID_CURSOR", "cursor is empty", null);
            return parsed;
        } catch (IllegalArgumentException | JsonParseException ex) {
            throw new ApiError("INVALID_CURSOR", "cursor is malformed", null);
        }
    }

    /** Produces a compact unified diff with 3 context lines; returns "" when identical. */
    static String unifiedDiff(String label, String before, String after) {
        String aText = before == null ? "" : before;
        String bText = after == null ? "" : after;
        if (aText.equals(bText)) return "";
        List<String> a = splitLines(aText);
        List<String> b = splitLines(bText);
        // shortcut: O(N*M) LCS skipped above 2M cells to bound memory/time on huge functions; falls back to full replacement hunk.
        List<DiffOp> ops = ((long) a.size() * b.size() <= 2_000_000L)
                ? lcsDiff(a, b)
                : fallbackDiff(a, b);
        return formatUnified(label, ops);
    }

    private static List<String> splitLines(String s) {
        if (s.isEmpty()) return List.of();
        String[] raw = s.split("\n", -1);
        int end = (raw.length > 0 && raw[raw.length - 1].isEmpty()) ? raw.length - 1 : raw.length;
        List<String> lines = new ArrayList<>(end);
        for (int i = 0; i < end; i++) lines.add(raw[i]);
        return lines;
    }

    private enum OpKind { EQ, DEL, ADD }

    private record DiffOp(OpKind kind, String line, int aLine, int bLine) {}

    private static List<DiffOp> lcsDiff(List<String> a, List<String> b) {
        int m = a.size(), n = b.size();
        int[][] dp = new int[m + 1][n + 1];
        for (int i = m - 1; i >= 0; i--) {
            String ai = a.get(i);
            for (int j = n - 1; j >= 0; j--) {
                dp[i][j] = ai.equals(b.get(j)) ? 1 + dp[i + 1][j + 1] : Math.max(dp[i + 1][j], dp[i][j + 1]);
            }
        }
        List<DiffOp> ops = new ArrayList<>(m + n);
        int i = 0, j = 0;
        while (i < m && j < n) {
            if (a.get(i).equals(b.get(j))) {
                ops.add(new DiffOp(OpKind.EQ, a.get(i), i + 1, j + 1));
                i++;
                j++;
            } else if (dp[i + 1][j] >= dp[i][j + 1]) {
                ops.add(new DiffOp(OpKind.DEL, a.get(i), i + 1, j + 1));
                i++;
            } else {
                ops.add(new DiffOp(OpKind.ADD, b.get(j), i + 1, j + 1));
                j++;
            }
        }
        while (i < m) {
            ops.add(new DiffOp(OpKind.DEL, a.get(i), i + 1, j + 1));
            i++;
        }
        while (j < n) {
            ops.add(new DiffOp(OpKind.ADD, b.get(j), i + 1, j + 1));
            j++;
        }
        return ops;
    }

    private static List<DiffOp> fallbackDiff(List<String> a, List<String> b) {
        List<DiffOp> ops = new ArrayList<>(a.size() + b.size());
        for (int i = 0; i < a.size(); i++) ops.add(new DiffOp(OpKind.DEL, a.get(i), i + 1, 1));
        for (int j = 0; j < b.size(); j++) ops.add(new DiffOp(OpKind.ADD, b.get(j), a.size() + 1, j + 1));
        return ops;
    }

    private static String formatUnified(String label, List<DiffOp> ops) {
        List<Integer> changed = new ArrayList<>();
        for (int idx = 0; idx < ops.size(); idx++) {
            if (ops.get(idx).kind != OpKind.EQ) changed.add(idx);
        }
        if (changed.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("--- a/").append(label).append('\n');
        sb.append("+++ b/").append(label).append('\n');
        int ctx = 3;
        int pos = 0;
        while (pos < changed.size()) {
            int start = Math.max(0, changed.get(pos) - ctx);
            int end = Math.min(ops.size() - 1, changed.get(pos) + ctx);
            while (pos + 1 < changed.size() && changed.get(pos + 1) - ctx <= end + 1) {
                pos++;
                end = Math.min(ops.size() - 1, changed.get(pos) + ctx);
            }
            int aStart = ops.get(start).aLine;
            int bStart = ops.get(start).bLine;
            int aCount = 0, bCount = 0;
            StringBuilder hunk = new StringBuilder();
            for (int k = start; k <= end; k++) {
                DiffOp op = ops.get(k);
                switch (op.kind) {
                    case EQ -> { aCount++; bCount++; hunk.append(' ').append(op.line).append('\n'); }
                    case DEL -> { aCount++; hunk.append('-').append(op.line).append('\n'); }
                    case ADD -> { bCount++; hunk.append('+').append(op.line).append('\n'); }
                }
            }
            sb.append("@@ -").append(aStart).append(',').append(aCount)
                    .append(" +").append(bStart).append(',').append(bCount).append(" @@\n");
            sb.append(hunk);
            pos++;
        }
        return sb.toString();
    }
}
