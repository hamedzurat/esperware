package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Owns the one MCP-visible program, decompiler, revisions, and serialized edit lifecycle. */
final class GhidraSessionService {
    private final ProgramManager programs;
    private final Project project;
    private final Gson gson = new Gson();
    private final Map<String, Variable> variableReferences = new HashMap<>();
    private Program program;
    private DecompInterface decompiler;
    private String sessionId;
    private long generation;
    private EditRecord latestEdit;

    GhidraSessionService(ProgramManager programs, Project project) {
        this.programs = programs;
        this.project = project;
    }

    synchronized Map<String, Object> programSession(Map<String, Object> args) throws Exception {
        Contract.requireVersion(args);
        String action = Contract.requiredString(args, "action");
        return switch (action) {
            case "open" -> open(Contract.requiredString(args, "program"));
            case "status" -> status(args);
            case "close" -> close(args);
            default -> throw new Contract.McpFault("INVALID_ACTION", "action must be open, status, or close", revisionOrNull());
        };
    }

    private Map<String, Object> open(String programPath) throws Exception {
        if (project == null || project.getProjectData() == null) {
            throw new Contract.McpFault("NO_PROJECT", "Open a Ghidra project before opening a program", null);
        }
        DomainFile file = project.getProjectData().getFile(programPath);
        if (file == null) throw new Contract.McpFault("PROGRAM_NOT_FOUND", "No project program at " + programPath, null);
        closeDecompiler();
        program = programs.openProgram(file, ProgramManager.OPEN_CURRENT);
        if (program == null) throw new Contract.McpFault("PROGRAM_OPEN_FAILED", "Ghidra could not open " + programPath, null);
        decompiler = new DecompInterface();
        decompiler.openProgram(program);
        generation++;
        sessionId = "s-" + UUID.randomUUID();
        latestEdit = null;
        variableReferences.clear();
        return Map.of("ok", true, "session_id", sessionId, "generation", generation,
                "revision", revision(), "program", program.getDomainFile().getPathname(),
                "limits", limits());
    }

    private Map<String, Object> status(Map<String, Object> args) {
        if (program != null && args.containsKey("session_id")) validateIdentity(args, false);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", true);
        result.put("runtime_live", true);
        result.put("is_open", program != null);
        if (program != null) {
            result.put("session_id", sessionId);
            result.put("generation", generation);
            result.put("revision", revision());
            result.put("program", program.getDomainFile().getPathname());
            result.put("latest_edit_id", latestEdit == null ? null : latestEdit.id);
        }
        result.put("limits", limits());
        return result;
    }

    private Map<String, Object> close(Map<String, Object> args) {
        validateIdentity(args, false);
        String closedId = sessionId;
        long closedGeneration = generation;
        closeDecompiler();
        program = null;
        sessionId = null;
        latestEdit = null;
        variableReferences.clear();
        return Map.of("ok", true, "session_closed", true,
                "session_id", closedId, "generation", closedGeneration);
    }

    synchronized Map<String, Object> inspect(Map<String, Object> args) {
        Contract.requireVersion(args);
        validateIdentity(args, true);
        String functionAddress = Contract.requiredString(args, "function_address");
        long revision = revision();
        Function function = functionAt(functionAddress);
        PageCursor cursor = PageCursor.from(args.get("cursor"), revision, functionAddress, gson);
        variableReferences.clear();

        List<Map<String, Object>> variables = new ArrayList<>();
        for (Variable variable : function.getAllVariables()) {
            long symbolId = variable.getSymbol().getID();
            String reference = "v:" + symbolId + ":" + revision;
            variableReferences.put(reference, variable);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("reference", reference);
            item.put("name", variable.getName());
            item.put("data_type", variable.getDataType().getDisplayName());
            item.put("storage", variable.getVariableStorage().toString());
            item.put("kind", variable instanceof ghidra.program.model.listing.Parameter ? "parameter" : "local");
            item.put("comment", variable.getComment());
            variables.add(item);
        }

        DecompileResults decompiled = decompiler.decompileFunction(
                function, Contract.DECOMPILE_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
        String code = "";
        String decompileStatus = "complete";
        String decompileError = null;
        if (decompiled == null) {
            decompileStatus = "failed";
            decompileError = "Decompiler returned no result";
        } else if (decompiled.isTimedOut()) {
            decompileStatus = "timed_out";
            decompileError = decompiled.getErrorMessage();
        } else if (!decompiled.decompileCompleted()) {
            decompileStatus = "failed";
            decompileError = decompiled.getErrorMessage();
        } else {
            code = decompiled.getDecompiledFunction().getC();
        }

        List<Map<String, Object>> navigation = navigation(function);
        int navEnd = Math.min(cursor.navigationOffset + Contract.NAVIGATION_PAGE_SIZE, navigation.size());
        List<Map<String, Object>> navigationPage = navigation.subList(cursor.navigationOffset, navEnd);
        int codeEnd = Math.min(cursor.codeOffset + Contract.PSEUDOCODE_PAGE_SIZE, code.length());
        String codePage = code.substring(Math.min(cursor.codeOffset, code.length()), codeEnd);
        boolean more = navEnd < navigation.size() || codeEnd < code.length();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("ok", true);
        response.put("revision", revision);
        response.put("function", Map.of("entry_address", function.getEntryPoint().toString(),
                "name", function.getName(), "signature", function.getPrototypeString(false, true),
                "comment", function.getComment() == null ? "" : function.getComment()));
        response.put("variables", variables);
        response.put("pseudocode", codePage);
        response.put("pseudocode_truncated", codeEnd < code.length());
        response.put("decompile_status", decompileStatus);
        if (decompileError != null) response.put("decompile_error", decompileError);
        response.put("navigation", navigationPage);
        response.put("navigation_total", navigation.size());
        response.put("navigation_truncated", navEnd < navigation.size());
        response.put("limits", limits());
        if (more) response.put("cursor", new PageCursor(revision, functionAddress, navEnd, codeEnd).encode(gson));
        return response;
    }

    synchronized Map<String, Object> edit(Map<String, Object> args) {
        Contract.requireVersion(args);
        validateIdentity(args, true);
        Map<String, Object> target = object(args.get("target"), "target");
        Map<String, Object> change = object(args.get("change"), "change");
        String targetKind = Contract.requiredString(target, "kind");
        String changeKind = Contract.requiredString(change, "kind");
        if (!targetKind.equals("function") && !targetKind.equals("variable")) {
            throw new Contract.McpFault("INVALID_TARGET", "target.kind must be function or variable", revision());
        }
        Function function = functionAt(Contract.requiredString(target, "function_address"));
        Variable variable = targetKind.equals("variable") ? resolveVariable(target, function) : null;
        if (changeKind.equals("signature") && !targetKind.equals("function")) {
            throw new Contract.McpFault("INVALID_CHANGE", "signature changes require a function target", revision());
        }
        if (changeKind.equals("type") && !targetKind.equals("variable")) {
            throw new Contract.McpFault("INVALID_CHANGE", "type changes require a variable target", revision());
        }
        long beforeRevision = revision();
        EditRecord record = capture(function, variable, targetKind, changeKind);
        int transaction = program.startTransaction("MCP " + changeKind);
        boolean committed = false;
        try {
            apply(function, variable, changeKind, change);
            program.endTransaction(transaction, true);
            committed = true;
        } catch (Exception failure) {
            program.endTransaction(transaction, false);
            throw new Contract.McpFault("EDIT_FAILED", failure.getMessage(), revision());
        }
        long newRevision = revision();
        record.id = "e-" + UUID.randomUUID();
        record.revision = newRevision;
        latestEdit = record;
        variableReferences.clear();
        decompiler.flushCache();
        Map<String, Object> decompile = decompileStatus(function);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", true);
        result.put("edit_id", record.id);
        result.put("revision", newRevision);
        result.put("edit_status", committed ? "committed" : "failed");
        result.put("decompile_status", decompile.get("status"));
        if (decompile.containsKey("error")) result.put("decompile_error", decompile.get("error"));
        result.put("previous_revision", beforeRevision);
        return result;
    }

    synchronized Map<String, Object> save(Map<String, Object> args) throws Exception {
        Contract.requireVersion(args);
        validateIdentity(args, true);
        program.save("Saved by ghidraMCP", TaskMonitor.DUMMY);
        return Map.of("ok", true, "revision", revision(), "save_status", "saved");
    }

    synchronized Map<String, Object> revert(Map<String, Object> args) {
        Contract.requireVersion(args);
        validateIdentity(args, true);
        String editId = Contract.requiredString(args, "edit_id");
        if (latestEdit == null || !latestEdit.id.equals(editId)) {
            throw new Contract.McpFault("EDIT_NOT_ELIGIBLE", "Only the latest eligible edit can be reverted", revision());
        }
        if (latestEdit.revision != revision()) {
            throw new Contract.McpFault("EDIT_NOT_ELIGIBLE", "A later mutation or undo/redo invalidated this revert", revision());
        }
        Function function = functionAt(latestEdit.functionAddress);
        Variable variable = latestEdit.symbolId == null ? null : variableBySymbolId(function, latestEdit.symbolId);
        EditRecord reverting = latestEdit;
        int transaction = program.startTransaction("Revert MCP edit " + editId);
        try {
            applyPrevious(function, variable, reverting);
            program.endTransaction(transaction, true);
        } catch (Exception failure) {
            program.endTransaction(transaction, false);
            throw new Contract.McpFault("REVERT_FAILED", failure.getMessage(), revision());
        }
        latestEdit = null;
        variableReferences.clear();
        long newRevision = revision();
        decompiler.flushCache();
        Map<String, Object> decompile = decompileStatus(function);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", true);
        result.put("reverted_edit_id", editId);
        result.put("revision", newRevision);
        result.put("revert_status", "committed");
        result.put("decompile_status", decompile.get("status"));
        if (decompile.containsKey("error")) result.put("decompile_error", decompile.get("error"));
        return result;
    }

    private void apply(Function function, Variable variable, String kind, Map<String, Object> change) throws Exception {
        String value = Contract.requiredValue(change, "value");
        switch (kind) {
            case "rename" -> {
                if (variable == null) function.setName(value, SourceType.USER_DEFINED);
                else variable.setName(value, SourceType.USER_DEFINED);
            }
            case "comment" -> {
                if (variable == null) function.setComment(value);
                else variable.setComment(value);
            }
            case "type" -> variable.setDataType(parseType(value), SourceType.USER_DEFINED);
            case "signature" -> setSignature(function, value);
            default -> throw new Contract.McpFault("INVALID_CHANGE", "change.kind must be rename, comment, type, or signature", revision());
        }
    }

    private void applyPrevious(Function function, Variable variable, EditRecord record) throws Exception {
        switch (record.changeKind) {
            case "rename" -> {
                if (record.symbolId == null) function.setName(record.before, SourceType.USER_DEFINED);
                else variable.setName(record.before, SourceType.USER_DEFINED);
            }
            case "comment" -> {
                if (record.symbolId == null) function.setComment(record.before);
                else variable.setComment(record.before);
            }
            case "type" -> variable.setDataType(parseType(record.before), SourceType.USER_DEFINED);
            case "signature" -> setSignature(function, record.before);
            default -> throw new IllegalStateException("Unknown edit kind " + record.changeKind);
        }
    }

    private void setSignature(Function function, String prototype) throws Exception {
        FunctionSignatureParser parser = new FunctionSignatureParser(program.getDataTypeManager(), null);
        FunctionDefinition definition = parser.parse((FunctionSignature) function.getSignature(), prototype);
        List<Variable> parameters = new ArrayList<>();
        for (ParameterDefinition parameter : definition.getArguments()) {
            parameters.add(new ParameterImpl(parameter.getName(), parameter.getDataType(), program, SourceType.USER_DEFINED));
        }
        function.setReturnType(definition.getReturnType(), SourceType.USER_DEFINED);
        function.updateFunction(null, null, parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true, SourceType.USER_DEFINED);
    }

    private DataType parseType(String type) throws Exception {
        return new DataTypeParser(null, program.getDataTypeManager(), null,
                DataTypeParser.AllowedDataTypes.ALL).parse(type);
    }

    private EditRecord capture(Function function, Variable variable, String targetKind, String changeKind) {
        EditRecord record = new EditRecord();
        record.functionAddress = function.getEntryPoint().toString();
        record.changeKind = changeKind;
        record.symbolId = variable == null ? null : variable.getSymbol().getID();
        record.before = switch (changeKind) {
            case "rename" -> variable == null ? function.getName() : variable.getName();
            case "comment" -> variable == null ? function.getComment() : variable.getComment();
            case "type" -> variable.getDataType().getPathName();
            case "signature" -> function.getPrototypeString(false, true);
            default -> throw new Contract.McpFault("INVALID_CHANGE", "Unsupported change kind", revision());
        };
        return record;
    }

    private Variable resolveVariable(Map<String, Object> target, Function function) {
        String reference = Contract.requiredString(target, "variable_ref");
        if (!reference.endsWith(":" + revision())) {
            throw new Contract.McpFault("STALE_REFERENCE", "Variable reference is bound to an earlier revision; inspect again", revision());
        }
        Variable supplied = variableReferences.get(reference);
        if (supplied == null) throw new Contract.McpFault("STALE_REFERENCE", "Variable reference is unknown; inspect again", revision());
        long id = supplied.getSymbol().getID();
        Variable resolved = null;
        for (Variable candidate : function.getAllVariables()) {
            if (candidate.getSymbol().getID() == id) {
                if (resolved != null) throw new Contract.McpFault("AMBIGUOUS_REFERENCE", "Variable reference resolves ambiguously", revision());
                resolved = candidate;
            }
        }
        if (resolved == null) throw new Contract.McpFault("STALE_REFERENCE", "Variable no longer exists; inspect again", revision());
        return resolved;
    }

    private Variable variableBySymbolId(Function function, long id) {
        for (Variable candidate : function.getAllVariables()) {
            if (candidate.getSymbol().getID() == id) return candidate;
        }
        throw new Contract.McpFault("STALE_REFERENCE", "Variable was changed by the edit; cannot safely revert", revision());
    }

    private Function functionAt(String addressText) {
        Address address = program.getAddressFactory().getAddress(addressText);
        Function function = address == null ? null : program.getFunctionManager().getFunctionAt(address);
        if (function == null) throw new Contract.McpFault("FUNCTION_NOT_FOUND", "No function entry at " + addressText, revision());
        return function;
    }

    private List<Map<String, Object>> navigation(Function function) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (Function callee : function.getCalledFunctions(TaskMonitor.DUMMY)) {
            items.add(Map.of("kind", "callee", "entry_address", callee.getEntryPoint().toString(), "name", callee.getName()));
        }
        for (Function caller : function.getCallingFunctions(TaskMonitor.DUMMY)) {
            items.add(Map.of("kind", "caller", "entry_address", caller.getEntryPoint().toString(), "name", caller.getName()));
        }
        for (Reference reference : program.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("kind", "xref");
            item.put("from_address", reference.getFromAddress().toString());
            item.put("reference_type", reference.getReferenceType().getName());
            Function containing = program.getFunctionManager().getFunctionContaining(reference.getFromAddress());
            if (containing != null) item.put("from_function", containing.getName());
            items.add(item);
        }
        return items;
    }

    private Map<String, Object> decompileStatus(Function function) {
        try {
            DecompileResults result = decompiler.decompileFunction(function,
                    Contract.DECOMPILE_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
            if (result != null && result.decompileCompleted()) return Map.of("status", "complete");
            String status = result != null && result.isTimedOut() ? "timed_out" : "failed";
            return Map.of("status", status, "error", result == null ? "No decompile result" : result.getErrorMessage());
        } catch (Exception failure) {
            return Map.of("status", "failed", "error", failure.getMessage() == null ? failure.toString() : failure.getMessage());
        }
    }

    private void validateIdentity(Map<String, Object> args, boolean checkRevision) {
        if (program == null || sessionId == null) throw new Contract.McpFault("NO_OPEN_SESSION", "Open a program session first", null);
        String suppliedSession = Contract.requiredString(args, "session_id");
        long suppliedGeneration = Contract.requiredLong(args, "generation");
        if (!sessionId.equals(suppliedSession) || generation != suppliedGeneration) {
            throw new Contract.McpFault("STALE_SESSION", "Session or generation is stale", revision());
        }
        if (checkRevision) {
            long expected = Contract.requiredLong(args, "expected_revision");
            if (expected != revision()) throw new Contract.McpFault("STALE_REVISION", "Revision mismatch; inspect again before retrying", revision());
        }
    }

    private long revision() { return program.getModificationNumber(); }
    private Long revisionOrNull() { return program == null ? null : revision(); }

    private static Map<String, Object> limits() {
        return Map.of("functions_per_inspection", 1,
                "navigation_results_per_page", Contract.NAVIGATION_PAGE_SIZE,
                "pseudocode_characters_per_page", Contract.PSEUDOCODE_PAGE_SIZE,
                "decompilation_timeout_seconds", Contract.DECOMPILE_TIMEOUT_SECONDS);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value, String name) {
        if (!(value instanceof Map<?, ?> map)) throw new Contract.McpFault("INVALID_ARGUMENT", name + " must be an object", null);
        return (Map<String, Object>) map;
    }

    private void closeDecompiler() {
        if (decompiler != null) {
            decompiler.closeProgram();
            decompiler.dispose();
            decompiler = null;
        }
    }

    private record PageCursor(long revision, String functionAddress, int navigationOffset, int codeOffset) {
        String encode(Gson gson) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(gson.toJson(this).getBytes(StandardCharsets.UTF_8));
        }

        static PageCursor from(Object input, long revision, String function, Gson gson) {
            if (input == null) return new PageCursor(revision, function, 0, 0);
            if (!(input instanceof String cursor)) throw new Contract.McpFault("INVALID_CURSOR", "cursor must be a string", revision);
            try {
                PageCursor decoded = gson.fromJson(new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8), PageCursor.class);
                if (decoded.revision != revision || !decoded.functionAddress.equals(function)) {
                    throw new Contract.McpFault("STALE_CURSOR", "Cursor belongs to another revision or function", revision);
                }
                if (decoded.navigationOffset < 0 || decoded.codeOffset < 0) throw new IllegalArgumentException("negative offset");
                return decoded;
            } catch (IllegalArgumentException | JsonParseException failure) {
                throw new Contract.McpFault("INVALID_CURSOR", "cursor is malformed", revision);
            }
        }
    }

    private static final class EditRecord {
        String id;
        String functionAddress;
        String changeKind;
        String before;
        Long symbolId;
        long revision;
    }
}
