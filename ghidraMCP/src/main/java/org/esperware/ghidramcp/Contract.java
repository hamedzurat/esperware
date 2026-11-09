package org.esperware.ghidramcp;

import java.util.Map;

final class Contract {
    static final int VERSION = 1;
    static final int NAVIGATION_PAGE_SIZE = 50;
    static final int PSEUDOCODE_PAGE_SIZE = 16_000;
    static final int DECOMPILE_TIMEOUT_SECONDS = 30;
    static final int SEARCH_FUNCTIONS_PER_PAGE = 20;
    static final int SEARCH_DECOMPILE_TIMEOUT_SECONDS = 1;
    static final int TYPES_PER_PAGE = 20;
    static final int TYPE_COMPONENTS_PER_TYPE = 100;

    private Contract() {}

    static void requireVersion(Map<String, Object> args) {
        Object version = args.get("contract_version");
        if (!(version instanceof Number number) || number.intValue() != VERSION) {
            throw new McpFault("UNSUPPORTED_CONTRACT", "contract_version must be 1", null);
        }
    }

    static String requiredString(Map<String, Object> args, String name) {
        Object value = args.get(name);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new McpFault("INVALID_ARGUMENT", name + " must be a non-empty string", null);
        }
        return text;
    }

    static String requiredValue(Map<String, Object> args, String name) {
        Object value = args.get(name);
        if (!(value instanceof String text)) {
            throw new McpFault("INVALID_ARGUMENT", name + " must be a string", null);
        }
        return text;
    }

    static long requiredLong(Map<String, Object> args, String name) {
        Object value = args.get(name);
        if (!(value instanceof Number number)) {
            throw new McpFault("INVALID_ARGUMENT", name + " must be an integer", null);
        }
        return number.longValue();
    }

    static final class McpFault extends RuntimeException {
        final String code;
        final Long currentRevision;

        McpFault(String code, String message, Long currentRevision) {
            super(message);
            this.code = code;
            this.currentRevision = currentRevision;
        }
    }
}
