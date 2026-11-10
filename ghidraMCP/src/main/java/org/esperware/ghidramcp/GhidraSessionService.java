package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.CommentType;
import ghidra.util.data.DataTypeParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/** Owns the one MCP-visible program, decompiler, revisions, and serialized edit lifecycle. */
final class GhidraSessionService {
    private final ProgramManager programs;
    private final Project project;
    private Program activeProgram;
    private final Gson gson = new Gson();
    private final Map<String, Variable> variableReferences = new HashMap<>();
    private final Map<String, GlobalReference> globalReferences = new HashMap<>();
    private Program program;
    private DecompInterface decompiler;
    private String sessionId;
    private long generation;
    private EditRecord latestEdit;

    GhidraSessionService(ProgramManager programs, Project project) {
        this.programs = programs;
        this.project = project;
    }

    synchronized void setActiveProgram(Program program) {
        activeProgram = program;
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
        Program active = activeProgram;
        if (active == null) active = programs.getCurrentProgram();
        if (active == null || !active.getDomainFile().getPathname().equals(file.getPathname())) {
            active = null;
            for (Program openProgram : programs.getAllOpenPrograms()) {
                if (openProgram.getDomainFile().getPathname().equals(file.getPathname())) {
                    active = openProgram;
                    break;
                }
            }
        }
        if (active != null) programs.openProgram(active, ProgramManager.OPEN_CURRENT);
        program = active != null ? active : programs.openProgram(file, ProgramManager.OPEN_CURRENT);
        if (program == null) throw new Contract.McpFault("PROGRAM_OPEN_FAILED", "Ghidra could not open " + programPath, null);
        decompiler = new DecompInterface();
        decompiler.openProgram(program);
        generation++;
        sessionId = "s-" + UUID.randomUUID();
        latestEdit = null;
        variableReferences.clear();
        globalReferences.clear();
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
        globalReferences.clear();
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
        globalReferences.clear();

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
        response.put("globals", globalVariables(function, revision));
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

    synchronized Map<String, Object> searchPseudocode(Map<String, Object> args) {
        Contract.requireVersion(args);
        validateIdentity(args, true);
        String query = Contract.requiredString(args, "query").trim();
        String scope = Contract.requiredString(args, "match_in");
        if (query.isEmpty() || query.length() > 256) {
            throw new Contract.McpFault("INVALID_QUERY", "query must contain 1 to 256 characters", revision());
        }
        if (!List.of("name", "signature", "pseudocode", "all").contains(scope)) {
            throw new Contract.McpFault("INVALID_SCOPE", "match_in must be name, signature, pseudocode, or all", revision());
        }
        long currentRevision = revision();
        SearchCursor cursor = SearchCursor.from(args.get("cursor"), currentRevision, query, scope, gson);
        String foldedQuery = query.toLowerCase(Locale.ROOT);
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        int functionOffset = 0;
        while (functionOffset < cursor.functionOffset && functions.hasNext()) {
            functions.next();
            functionOffset++;
        }

        List<Map<String, Object>> matches = new ArrayList<>();
        List<Map<String, Object>> issues = new ArrayList<>();
        int scanned = 0;
        while (scanned < Contract.SEARCH_FUNCTIONS_PER_PAGE && functions.hasNext()) {
            Function function = functions.next();
            functionOffset++;
            scanned++;
            if (function.isExternal()) continue;

            String name = function.getName();
            String signature = function.getPrototypeString(false, true);
            String matchKind = null;
            String matchText = null;
            if ((scope.equals("name") || scope.equals("all"))
                    && name.toLowerCase(Locale.ROOT).contains(foldedQuery)) {
                matchKind = "name";
                matchText = name;
            } else if ((scope.equals("signature") || scope.equals("all"))
                    && signature.toLowerCase(Locale.ROOT).contains(foldedQuery)) {
                matchKind = "signature";
                matchText = signature;
            }

            if (matchKind == null && (scope.equals("pseudocode") || scope.equals("all"))) {
                DecompileResults result = decompiler.decompileFunction(
                        function, Contract.SEARCH_DECOMPILE_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
                if (result == null || !result.decompileCompleted()) {
                    Map<String, Object> issue = new LinkedHashMap<>();
                    issue.put("entry_address", function.getEntryPoint().toString());
                    issue.put("name", name);
                    issue.put("status", result != null && result.isTimedOut() ? "timed_out" : "failed");
                    issue.put("message", result == null ? "No decompile result" : result.getErrorMessage());
                    issues.add(issue);
                } else {
                    String pseudocode = result.getDecompiledFunction().getC();
                    int matchIndex = pseudocode.toLowerCase(Locale.ROOT).indexOf(foldedQuery);
                    if (matchIndex >= 0) {
                        matchKind = "pseudocode";
                        matchText = excerpt(pseudocode, matchIndex, query.length());
                    }
                }
            }

            if (matchKind != null) {
                Map<String, Object> match = new LinkedHashMap<>();
                match.put("entry_address", function.getEntryPoint().toString());
                match.put("name", name);
                match.put("signature", signature);
                match.put("match_in", matchKind);
                match.put("excerpt", matchText);
                matches.add(match);
            }
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("ok", true);
        response.put("revision", currentRevision);
        response.put("query", query);
        response.put("match_in", scope);
        response.put("functions_scanned", scanned);
        response.put("matches", matches);
        response.put("decompile_issues", issues);
        response.put("limits", Map.of("functions_scanned_per_page", Contract.SEARCH_FUNCTIONS_PER_PAGE,
                "search_decompile_timeout_seconds", Contract.SEARCH_DECOMPILE_TIMEOUT_SECONDS));
        if (functions.hasNext()) {
            response.put("cursor", new SearchCursor(currentRevision, query, scope, functionOffset).encode(gson));
        }
        return response;
    }

    synchronized Map<String, Object> searchTypes(Map<String, Object> args) {
        Contract.requireVersion(args);
        validateIdentity(args, true);
        String query = Contract.requiredString(args, "query").trim();
        if (query.isEmpty() || query.length() > 256) {
            throw new Contract.McpFault("INVALID_QUERY", "query must contain 1 to 256 characters", revision());
        }
        long currentRevision = revision();
        TypeCursor cursor = TypeCursor.from(args.get("cursor"), currentRevision, query, gson);
        String foldedQuery = query.toLowerCase(Locale.ROOT);
        List<DataType> matches = new ArrayList<>();
        var allTypes = program.getDataTypeManager().getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType type = allTypes.next();
            if (type.getName().toLowerCase(Locale.ROOT).contains(foldedQuery)
                    || type.getPathName().toLowerCase(Locale.ROOT).contains(foldedQuery)) {
                matches.add(type);
            }
        }
        matches.sort(Comparator.comparing(DataType::getPathName, String.CASE_INSENSITIVE_ORDER));

        int end = Math.min(cursor.offset + Contract.TYPES_PER_PAGE, matches.size());
        List<Map<String, Object>> page = new ArrayList<>();
        for (int index = cursor.offset; index < end; index++) page.add(typeDetails(matches.get(index)));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("ok", true);
        response.put("revision", currentRevision);
        response.put("query", query);
        response.put("types", page);
        response.put("total_matches", matches.size());
        response.put("limits", Map.of("types_per_page", Contract.TYPES_PER_PAGE,
                "components_per_type", Contract.TYPE_COMPONENTS_PER_TYPE));
        if (end < matches.size()) response.put("cursor", new TypeCursor(currentRevision, query, end).encode(gson));
        return response;
    }

    private Map<String, Object> typeDetails(DataType type) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", type.getName());
        result.put("data_type_path", type.getPathName());
        result.put("display_name", type.getDisplayName());
        result.put("kind", typeKind(type));
        result.put("length_bytes", type.getLength());
        result.put("description", type.getDescription() == null ? "" : type.getDescription());

        if (type instanceof Composite composite) {
            DataTypeComponent[] components = composite.getComponents();
            List<Map<String, Object>> fields = new ArrayList<>();
            int end = Math.min(components.length, Contract.TYPE_COMPONENTS_PER_TYPE);
            for (int index = 0; index < end; index++) {
                DataTypeComponent component = components[index];
                Map<String, Object> field = new LinkedHashMap<>();
                field.put("ordinal", component.getOrdinal());
                field.put("offset_bytes", component.getOffset());
                field.put("name", component.getFieldName());
                field.put("data_type", component.getDataType().getDisplayName());
                field.put("data_type_path", component.getDataType().getPathName());
                field.put("length_bytes", component.getLength());
                field.put("comment", component.getComment());
                field.put("bit_field", component.isBitFieldComponent());
                fields.add(field);
            }
            result.put("fields", fields);
            result.put("fields_truncated", components.length > end);
        } else if (type instanceof ghidra.program.model.data.Enum enumType) {
            String[] names = enumType.getNames();
            long[] values = enumType.getValues();
            List<Map<String, Object>> entries = new ArrayList<>();
            int end = Math.min(names.length, Contract.TYPE_COMPONENTS_PER_TYPE);
            for (int index = 0; index < end; index++) {
                entries.add(Map.of("name", names[index], "value", values[index]));
            }
            result.put("values", entries);
            result.put("values_truncated", names.length > end);
        } else if (type instanceof TypedefDataType typedef) {
            result.put("base_type", typedef.getDataType().getDisplayName());
            result.put("base_type_path", typedef.getDataType().getPathName());
        } else if (type instanceof Pointer pointer && pointer.getDataType() != null) {
            result.put("points_to", pointer.getDataType().getDisplayName());
            result.put("points_to_path", pointer.getDataType().getPathName());
        } else if (type instanceof Array array) {
            result.put("element_type", array.getDataType().getDisplayName());
            result.put("element_type_path", array.getDataType().getPathName());
            result.put("element_count", array.getNumElements());
        }
        return result;
    }

    private String typeKind(DataType type) {
        if (type instanceof Structure) return "structure";
        if (type instanceof Union) return "union";
        if (type instanceof Composite) return "composite";
        if (type instanceof ghidra.program.model.data.Enum) return "enum";
        if (type instanceof TypedefDataType) return "typedef";
        if (type instanceof Pointer) return "pointer";
        if (type instanceof Array) return "array";
        return "scalar";
    }

    private static String excerpt(String text, int matchStart, int matchLength) {
        int start = Math.max(0, matchStart - 80);
        int end = Math.min(text.length(), matchStart + matchLength + 120);
        return text.substring(start, end).strip();
    }

    synchronized Map<String, Object> edit(Map<String, Object> args) {
        Contract.requireVersion(args);
        validateIdentity(args, true);
        Map<String, Object> target = object(args.get("target"), "target");
        Map<String, Object> change = object(args.get("change"), "change");
        String targetKind = Contract.requiredString(target, "kind");
        String changeKind = Contract.requiredString(change, "kind");
        if (!List.of("function", "variable", "global").contains(targetKind)) {
            throw new Contract.McpFault("INVALID_TARGET", "target.kind must be function, variable, or global", revision());
        }
        Function function = functionAt(Contract.requiredString(target, "function_address"));
        Variable variable = targetKind.equals("variable") ? resolveVariable(target, function) : null;
        GlobalReference global = targetKind.equals("global") ? resolveGlobal(target, function) : null;
        if (changeKind.equals("signature") && !targetKind.equals("function")) {
            throw new Contract.McpFault("INVALID_CHANGE", "signature changes require a function target", revision());
        }
        if (changeKind.equals("type") && !List.of("variable", "global").contains(targetKind)) {
            throw new Contract.McpFault("INVALID_CHANGE", "type changes require a variable or global target", revision());
        }
        long beforeRevision = revision();
        EditRecord record = capture(function, variable, global, targetKind, changeKind);
        int transaction = program.startTransaction("MCP " + changeKind);
        boolean committed = false;
        try {
            apply(function, variable, global, changeKind, change);
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
        globalReferences.clear();
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
        Variable variable = latestEdit.targetKind.equals("variable")
                ? variableBySymbolId(function, latestEdit.symbolId) : null;
        GlobalReference global = latestEdit.targetKind.equals("global")
                ? globalBySymbolId(latestEdit.symbolId, latestEdit.globalAddress, function) : null;
        EditRecord reverting = latestEdit;
        int transaction = program.startTransaction("Revert MCP edit " + editId);
        try {
            applyPrevious(function, variable, global, reverting);
            program.endTransaction(transaction, true);
        } catch (Exception failure) {
            program.endTransaction(transaction, false);
            throw new Contract.McpFault("REVERT_FAILED", failure.getMessage(), revision());
        }
        latestEdit = null;
        variableReferences.clear();
        globalReferences.clear();
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

    private void apply(Function function, Variable variable, GlobalReference global,
            String kind, Map<String, Object> change) throws Exception {
        String value = Contract.requiredValue(change, "value");
        switch (kind) {
            case "rename" -> {
                if (global != null) global.symbol.setName(value, SourceType.USER_DEFINED);
                else if (variable == null) function.setName(value, SourceType.USER_DEFINED);
                else variable.setName(value, SourceType.USER_DEFINED);
            }
            case "comment" -> {
                if (global != null) global.data.setComment(CommentType.EOL, value);
                else if (variable == null) function.setComment(value);
                else variable.setComment(value);
            }
            case "type" -> {
                DataType type = parseType(value);
                if (global != null) setGlobalDataType(global, type, comments(global.data));
                else variable.setDataType(type, SourceType.USER_DEFINED);
            }
            case "signature" -> setSignature(function, value);
            default -> throw new Contract.McpFault("INVALID_CHANGE", "change.kind must be rename, comment, type, or signature", revision());
        }
    }

    private void applyPrevious(Function function, Variable variable, GlobalReference global,
            EditRecord record) throws Exception {
        switch (record.changeKind) {
            case "rename" -> {
                if (record.targetKind.equals("global")) global.symbol.setName(record.before, SourceType.USER_DEFINED);
                else if (record.symbolId == null) function.setName(record.before, SourceType.USER_DEFINED);
                else variable.setName(record.before, SourceType.USER_DEFINED);
            }
            case "comment" -> {
                if (record.targetKind.equals("global")) global.data.setComment(CommentType.EOL, record.before);
                else if (record.symbolId == null) function.setComment(record.before);
                else variable.setComment(record.before);
            }
            case "type" -> {
                DataType type = parseType(record.before);
                if (record.targetKind.equals("global")) {
                    setGlobalDataType(global, type, record.globalComments, record.globalLength);
                } else {
                    variable.setDataType(type, SourceType.USER_DEFINED);
                }
            }
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
        DataType direct = program.getDataTypeManager().getDataType(type);
        if (direct != null) return direct;
        return new DataTypeParser(null, program.getDataTypeManager(), null,
                DataTypeParser.AllowedDataTypes.ALL).parse(type);
    }

    private EditRecord capture(Function function, Variable variable, GlobalReference global,
            String targetKind, String changeKind) {
        EditRecord record = new EditRecord();
        record.functionAddress = function.getEntryPoint().toString();
        record.targetKind = targetKind;
        record.changeKind = changeKind;
        if (global != null) record.symbolId = global.symbol.getID();
        else if (variable != null) record.symbolId = variable.getSymbol().getID();
        if (global != null) {
            record.globalAddress = global.data.getAddress().toString();
            record.globalLength = global.data.getLength();
            if (changeKind.equals("type")) record.globalComments = comments(global.data);
        }
        record.before = switch (changeKind) {
            case "rename" -> global != null ? global.symbol.getName()
                    : variable == null ? function.getName() : variable.getName();
            case "comment" -> global != null ? global.data.getComment(CommentType.EOL)
                    : variable == null ? function.getComment() : variable.getComment();
            case "type" -> global != null ? global.data.getDataType().getPathName()
                    : variable.getDataType().getPathName();
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

    private GlobalReference globalBySymbolId(Long symbolId, String addressText, Function function) {
        if (symbolId == null || addressText == null) {
            throw new Contract.McpFault("STALE_REFERENCE", "Global edit location is missing", revision());
        }
        Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
        Address address = program.getAddressFactory().getAddress(addressText);
        Data data = address == null ? null : program.getListing().getDefinedDataAt(address);
        if (symbol == null || data == null || !symbol.isGlobal()) {
            throw new Contract.McpFault("STALE_REFERENCE", "Global symbol or data was changed; cannot safely revert", revision());
        }
        return new GlobalReference(symbol, data, function.getEntryPoint().toString());
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

    private List<Map<String, Object>> globalVariables(Function function, long revision) {
        Map<Long, GlobalReference> found = new TreeMap<>();
        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            for (Reference reference : program.getReferenceManager().getReferencesFrom(instruction.getAddress())) {
                if (!reference.getReferenceType().isData()) continue;
                Data data = program.getListing().getDefinedDataContaining(reference.getToAddress());
                if (data == null) continue;
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(data.getAddress());
                if (symbol == null || !symbol.isGlobal() || symbol.getSymbolType() == SymbolType.FUNCTION) continue;
                found.putIfAbsent(symbol.getID(), new GlobalReference(symbol, data, function.getEntryPoint().toString()));
            }
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (GlobalReference global : found.values()) {
            String reference = "g:" + global.symbol.getID() + ":"
                    + function.getEntryPoint() + ":" + revision;
            globalReferences.put(reference, global);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("reference", reference);
            item.put("name", global.symbol.getName());
            item.put("address", global.data.getAddress().toString());
            item.put("data_type", global.data.getDataType().getDisplayName());
            item.put("data_type_path", global.data.getDataType().getPathName());
            item.put("length_bytes", global.data.getLength());
            item.put("comment", global.data.getComment(CommentType.EOL));
            result.add(item);
        }
        return result;
    }

    private GlobalReference resolveGlobal(Map<String, Object> target, Function function) {
        String reference = Contract.requiredString(target, "global_ref");
        if (!reference.endsWith(":" + revision())) {
            throw new Contract.McpFault("STALE_REFERENCE", "Global reference is bound to an earlier revision; inspect again", revision());
        }
        GlobalReference global = globalReferences.get(reference);
        if (global == null || !global.functionAddress.equals(function.getEntryPoint().toString())) {
            throw new Contract.McpFault("STALE_REFERENCE", "Global reference is unknown for this function; inspect again", revision());
        }
        Symbol currentSymbol = program.getSymbolTable().getSymbol(global.symbol.getID());
        Data currentData = program.getListing().getDefinedDataAt(global.data.getAddress());
        if (currentSymbol == null || currentData == null) {
            throw new Contract.McpFault("STALE_REFERENCE", "Global symbol or data no longer exists", revision());
        }
        return new GlobalReference(currentSymbol, currentData, global.functionAddress);
    }

    private Map<CommentType, String> comments(Data data) {
        Map<CommentType, String> result = new EnumMap<>(CommentType.class);
        for (CommentType type : CommentType.values()) {
            String comment = data.getComment(type);
            if (comment != null) result.put(type, comment);
        }
        return result;
    }

    private void setGlobalDataType(GlobalReference global, DataType type, Map<CommentType, String> comments)
            throws Exception {
        setGlobalDataType(global, type, comments, global.data.getLength());
    }

    private void setGlobalDataType(GlobalReference global, DataType type, Map<CommentType, String> comments,
            int allowedLength) throws Exception {
        Data oldData = program.getListing().getDefinedDataAt(global.data.getAddress());
        if (oldData == null) throw new Contract.McpFault("GLOBAL_DATA_NOT_DEFINED", "Global data must be defined before changing its type", revision());
        int oldLength = oldData.getLength();
        int newLength = type.getLength();
        if (newLength <= 0 || newLength > allowedLength) {
            throw new Contract.McpFault("UNSAFE_GLOBAL_TYPE", "New global data type must have a fixed size no larger than the existing data", revision());
        }
        Address start = oldData.getAddress();
        Address end = start.add(Math.max(oldLength, newLength) - 1L);
        program.getListing().clearCodeUnits(start, end, false);
        Data newData = program.getListing().createData(start, type);
        for (Map.Entry<CommentType, String> comment : comments.entrySet()) {
            newData.setComment(comment.getKey(), comment.getValue());
        }
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

    private record SearchCursor(long revision, String query, String scope, int functionOffset) {
        String encode(Gson gson) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(gson.toJson(this).getBytes(StandardCharsets.UTF_8));
        }

        static SearchCursor from(Object input, long revision, String query, String scope, Gson gson) {
            if (input == null) return new SearchCursor(revision, query, scope, 0);
            if (!(input instanceof String cursor)) throw new Contract.McpFault("INVALID_CURSOR", "cursor must be a string", revision);
            try {
                SearchCursor decoded = gson.fromJson(new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8), SearchCursor.class);
                if (decoded == null || decoded.revision != revision
                        || !query.equals(decoded.query) || !scope.equals(decoded.scope)) {
                    throw new Contract.McpFault("STALE_CURSOR", "Cursor belongs to another revision or search", revision);
                }
                if (decoded.functionOffset < 0) throw new IllegalArgumentException("negative function offset");
                return decoded;
            } catch (IllegalArgumentException | JsonParseException failure) {
                throw new Contract.McpFault("INVALID_CURSOR", "cursor is malformed", revision);
            }
        }
    }

    private record TypeCursor(long revision, String query, int offset) {
        String encode(Gson gson) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(gson.toJson(this).getBytes(StandardCharsets.UTF_8));
        }

        static TypeCursor from(Object input, long revision, String query, Gson gson) {
            if (input == null) return new TypeCursor(revision, query, 0);
            if (!(input instanceof String cursor)) throw new Contract.McpFault("INVALID_CURSOR", "cursor must be a string", revision);
            try {
                TypeCursor decoded = gson.fromJson(new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8), TypeCursor.class);
                if (decoded == null || decoded.revision != revision || !query.equals(decoded.query)) {
                    throw new Contract.McpFault("STALE_CURSOR", "Cursor belongs to another revision or type query", revision);
                }
                if (decoded.offset < 0) throw new IllegalArgumentException("negative offset");
                return decoded;
            } catch (IllegalArgumentException | JsonParseException failure) {
                throw new Contract.McpFault("INVALID_CURSOR", "cursor is malformed", revision);
            }
        }
    }

    private static final class GlobalReference {
        final Symbol symbol;
        final Data data;
        final String functionAddress;

        GlobalReference(Symbol symbol, Data data, String functionAddress) {
            this.symbol = symbol;
            this.data = data;
            this.functionAddress = functionAddress;
        }
    }

    private static final class EditRecord {
        String id;
        String functionAddress;
        String targetKind;
        String changeKind;
        String before;
        Long symbolId;
        String globalAddress;
        int globalLength;
        Map<CommentType, String> globalComments = Map.of();
        long revision;
    }
}
