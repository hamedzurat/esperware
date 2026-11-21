package org.esperware.ghidramcp;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.data.DataTypeParser;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Write-enabled mutation service enforcing AccessMode, CAS version checks, transactions, and inverse ops. */
final class EditService {
    private static final int DECOMPILE_TIMEOUT_SEC = 30;
    private static final int MAX_BATCH_OPS = 50;

    private final ProgramWorkspace ws;
    private final VersionStore store;

    EditService(ProgramWorkspace ws, VersionStore store) {
        this.ws = ws;
        this.store = store;
    }

    Map<String, Object> applyEdits(ApiError.AccessMode mode, String actor, Map<String, Object> args) throws Exception {
        requireWrite(mode);
        long expected = ApiError.reqLong(args, "expected_version", store.currentVersion());
        String reason = ApiError.optStr(args, "reason");
        List<Map<String, Object>> edits = ApiError.reqMapList(args, "edits", MAX_BATCH_OPS);

        return ws.withWriteLock(() -> {
            long current = store.currentVersion();
            if (expected != current) {
                throw new ApiError("STALE_VERSION",
                        "Version mismatch: expected " + expected + ", current is " + current, current);
            }
            return executeBatch("apply_edits", actor, reason, edits);
        });
    }

    Map<String, Object> defineType(ApiError.AccessMode mode, String actor, Map<String, Object> args) throws Exception {
        requireWrite(mode);
        long expected = ApiError.reqLong(args, "expected_version", store.currentVersion());
        String cDecl = ApiError.reqStr(args, "c_declaration");
        String catText = ApiError.optStr(args, "category");
        String categoryPath = catText == null ? "/mcp" : (catText.startsWith("/") ? catText : "/" + catText);
        String reason = ApiError.optStr(args, "reason");

        return ws.withWriteLock(() -> {
            long current = store.currentVersion();
            if (expected != current) {
                throw new ApiError("STALE_VERSION",
                        "Version mismatch: expected " + expected + ", current is " + current, current);
            }
            Program p = ws.program();
            DataTypeManager targetDtm = p.getDataTypeManager();
            List<DataType> parsedTypes = new ArrayList<>();
            try (StandAloneDataTypeManager tempDtm = new StandAloneDataTypeManager("mcp_parse")) {
                CParser parser = new CParser(tempDtm, true, new DataTypeManager[] {targetDtm});
                parser.parse(new ByteArrayInputStream(cDecl.getBytes(StandardCharsets.UTF_8)));
                if (!parser.didParseSucceed()) {
                    throw new ApiError("INVALID_TYPE_DECLARATION",
                            "C parse failed: " + parser.getParseMessages(), current);
                }
                Set<String> seenNames = new LinkedHashSet<>();
                for (Map<String, DataType> bucket : List.of(
                        parser.getComposites(), parser.getEnums(), parser.getTypes())) {
                    if (bucket == null) continue;
                    for (DataType dt : bucket.values()) {
                        if (dt != null && seenNames.add(dt.getPathName())) parsedTypes.add(dt);
                    }
                }
                if (parsedTypes.isEmpty() && parser.getLastDataType() != null) {
                    parsedTypes.add(parser.getLastDataType());
                }
                if (parsedTypes.isEmpty()) {
                    throw new ApiError("INVALID_TYPE_DECLARATION", "No data type found in c_declaration", current);
                }

                List<Map<String, Object>> defined = new ArrayList<>();
                List<Map<String, Object>> inverseOps = new ArrayList<>();
                CategoryPath cat = new CategoryPath(categoryPath);
                int tx = p.startTransaction("mcp:define_type");
                try {
                    for (DataType dt : parsedTypes) {
                        DataType copy = dt.copy(targetDtm);
                        copy.setCategoryPath(cat);
                        String destPath = new CategoryPath(cat, copy.getName()).getPath();
                        boolean existedBefore = targetDtm.getDataType(destPath) != null;
                        DataType resolved = targetDtm.resolve(copy, DataTypeConflictHandler.REPLACE_HANDLER);
                        defined.add(Map.of(
                                "name", resolved.getName(),
                                "path", resolved.getPathName(),
                                "size", resolved.getLength()));
                        if (!existedBefore) {
                            // shortcut: define_type revert removes newly created types; restoring overwritten composite fields requires .gpr checkpoint.
                            inverseOps.add(Map.of("op", "remove_type", "path", resolved.getPathName()));
                        }
                    }
                    p.endTransaction(tx, true);
                } catch (Exception ex) {
                    p.endTransaction(tx, false);
                    throw new ApiError("EDIT_FAILED", ex.getMessage(), current);
                }
                ws.invalidateCache();
                Collections.reverse(inverseOps);
                long newVer = store.recordVersion(actor, "define_type", reason,
                        List.of(Map.of("op", "define_type", "category", categoryPath, "c_declaration", cDecl)),
                        inverseOps, List.of());
                return Map.of("ok", true, "version", newVer, "previous_version", current, "defined_types", defined);
            }
        });
    }

    Map<String, Object> revert(ApiError.AccessMode mode, String actor, Map<String, Object> args) throws Exception {
        requireWrite(mode);
        long expected = ApiError.reqLong(args, "expected_version", store.currentVersion());
        long toVersion = ApiError.reqLong(args, "to_version", store.currentVersion());
        String reason = ApiError.optStr(args, "reason");

        return ws.withWriteLock(() -> {
            long current = store.currentVersion();
            if (expected != current) {
                throw new ApiError("STALE_VERSION",
                        "Version mismatch: expected " + expected + ", current is " + current, current);
            }
            if (toVersion < 0 || toVersion >= current) {
                throw new ApiError("INVALID_ARGUMENT",
                        "to_version must be >= 0 and < current version (" + current + ")", current);
            }
            List<Map<String, Object>> ops = store.inverseOpsRange(toVersion, current);
            if (ops.isEmpty()) {
                throw new ApiError("REVERT_UNAVAILABLE", "No reversible operations between v" + toVersion + " and v" + current, current);
            }
            String effectiveReason = reason != null ? reason : "revert to v" + toVersion;
            Map<String, Object> res = executeBatch("revert", actor, effectiveReason, ops);
            res.put("reverted_to", toVersion);
            return res;
        });
    }

    Map<String, Object> saveCheckpoint(ApiError.AccessMode mode, String actor, Map<String, Object> args) throws Exception {
        requireWrite(mode);
        String label = ApiError.optStr(args, "label");
        return ws.withWriteLock(() -> {
            ws.save();
            long ver = store.currentVersion();
            store.tagCheckpoint(ver, label);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", ver);
            out.put("saved", true);
            out.put("label", label == null ? "checkpoint-v" + ver : label);
            return out;
        });
    }

    private Map<String, Object> executeBatch(
            String operation,
            String actor,
            String reason,
            List<Map<String, Object>> ops) throws Exception {
        Program p = ws.program();
        long current = store.currentVersion();

        // Pre-resolve touched functions & capture before_c once per function
        Map<String, Function> touchedFunctions = new LinkedHashMap<>();
        for (Map<String, Object> op : ops) {
            Function fn = findTouchedFunction(op);
            if (fn != null) touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
        }
        Map<String, String> beforeCode = new LinkedHashMap<>();
        for (Map.Entry<String, Function> e : touchedFunctions.entrySet()) {
            var d = ws.decompileCached(e.getValue(), DECOMPILE_TIMEOUT_SEC);
            beforeCode.put(e.getKey(), "complete".equals(d.status()) ? d.code() : null);
        }

        List<Map<String, Object>> inverseOps = new ArrayList<>();
        Map<String, HighFunction> liveHfCache = new HashMap<>();
        Map<String, Map<String, String>> varRenameAliases = new HashMap<>();

        int tx = p.startTransaction("mcp:" + operation);
        try {
            for (Map<String, Object> op : ops) {
                Map<String, Object> inv = applyOp(op, liveHfCache, varRenameAliases);
                if (inv != null) inverseOps.add(inv);
            }
            p.endTransaction(tx, true);
        } catch (ApiError err) {
            p.endTransaction(tx, false);
            throw new ApiError(err.code, err.getMessage(), current);
        } catch (Exception ex) {
            p.endTransaction(tx, false);
            throw new ApiError("EDIT_FAILED", ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage(), current);
        }

        ws.invalidateCache();

        List<VersionStore.FunctionDiff> storedDiffs = new ArrayList<>();
        List<Map<String, Object>> apiDiffs = new ArrayList<>();
        for (Map.Entry<String, Function> e : touchedFunctions.entrySet()) {
            String addr = e.getKey();
            Function fn = e.getValue();
            ProgramWorkspace.LiveDecompile after = ws.decompileFresh(fn, DECOMPILE_TIMEOUT_SEC);
            String before = beforeCode.get(addr);
            String afterText = "complete".equals(after.status()) ? after.code() : null;
            String diff = (before != null && afterText != null)
                    ? ApiError.unifiedDiff(fn.getName() + " @ " + addr, before, afterText)
                    : "";
            storedDiffs.add(new VersionStore.FunctionDiff(addr, fn.getName(), before, afterText, diff, after.status()));

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("function_address", addr);
            entry.put("function_name", fn.getName());
            entry.put("decompile_status", after.status());
            if (after.error() != null) entry.put("decompile_error", after.error());
            entry.put("diff", diff);
            entry.put("variables", ws.extractVariables(fn, after.highFunction()));
            apiDiffs.add(entry);
        }

        Collections.reverse(inverseOps);
        long newVersion = store.recordVersion(actor, operation, reason, ops, inverseOps, storedDiffs);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("version", newVersion);
        out.put("previous_version", current);
        out.put("diffs", apiDiffs);
        return out;
    }

    private Function findTouchedFunction(Map<String, Object> op) {
        String kind = ApiError.reqStr(op, "op");
        return switch (kind) {
            case "rename_function", "set_signature" -> ws.resolveFunction(ApiError.reqStr(op, "target"));
            case "rename_var", "set_var_type" -> ws.resolveFunction(ApiError.reqStr(op, "function"));
            case "set_comment" -> {
                String ctype = ApiError.optStr(op, "comment_type");
                if ("var".equals(ctype) || "function".equals(ctype) || "plate".equals(ctype) || ctype == null) {
                    String target = ApiError.reqStr(op, "target");
                    Address a = ws.parseAddress(target);
                    yield a != null ? ws.program().getFunctionManager().getFunctionContaining(a) : ws.resolveFunction(target);
                }
                Address a = ws.parseAddress(ApiError.reqStr(op, "target"));
                yield a == null ? null : ws.program().getFunctionManager().getFunctionContaining(a);
            }
            case "rename_global", "set_global_type" -> {
                String fnHint = ApiError.optStr(op, "function");
                yield fnHint == null ? null : ws.resolveFunction(fnHint);
            }
            case "remove_type" -> null;
            default -> throw new ApiError("INVALID_ARGUMENT", "Unsupported edit op: " + kind, store.currentVersion());
        };
    }

    private Map<String, Object> applyOp(
            Map<String, Object> op,
            Map<String, HighFunction> liveHfCache,
            Map<String, Map<String, String>> varRenameAliases) throws Exception {
        String kind = ApiError.reqStr(op, "op");
        Program p = ws.program();

        return switch (kind) {
            case "rename_function" -> {
                Function fn = ws.resolveFunction(ApiError.reqStr(op, "target"));
                String oldName = fn.getName();
                String newName = ApiError.reqStr(op, "new_name");
                fn.setName(newName, SourceType.USER_DEFINED);
                yield Map.of("op", "rename_function", "target", fn.getEntryPoint().toString(), "new_name", oldName);
            }
            case "rename_var" -> {
                Function fn = ws.resolveFunction(ApiError.reqStr(op, "function"));
                String fnAddr = fn.getEntryPoint().toString();
                String requestedName = ApiError.reqStr(op, "var_name");
                String newName = ApiError.reqStr(op, "new_name");
                String effectiveName = varRenameAliases.getOrDefault(fnAddr, Map.of())
                        .getOrDefault(requestedName, requestedName);
                VarHandle vh = resolveVar(fn, effectiveName, liveHfCache);
                String oldName = vh.name();
                vh.rename(newName);
                varRenameAliases.computeIfAbsent(fnAddr, k -> new HashMap<>()).put(requestedName, newName);
                varRenameAliases.get(fnAddr).put(newName, newName);
                liveHfCache.remove(fnAddr);
                yield Map.of("op", "rename_var", "function", fnAddr, "var_name", newName, "new_name", oldName);
            }
            case "set_var_type" -> {
                Function fn = ws.resolveFunction(ApiError.reqStr(op, "function"));
                String fnAddr = fn.getEntryPoint().toString();
                String requestedName = ApiError.reqStr(op, "var_name");
                String effectiveName = varRenameAliases.getOrDefault(fnAddr, Map.of())
                        .getOrDefault(requestedName, requestedName);
                DataType dt = parseType(ApiError.reqStr(op, "type"));
                VarHandle vh = resolveVar(fn, effectiveName, liveHfCache);
                String oldPath = vh.dataTypePath();
                vh.setType(dt);
                liveHfCache.remove(fnAddr);
                yield Map.of("op", "set_var_type", "function", fnAddr, "var_name", vh.name(), "type", oldPath);
            }
            case "rename_global" -> {
                GlobalHandle gh = resolveGlobal(ApiError.reqStr(op, "target"));
                String oldName = gh.symbol.getName();
                String newName = ApiError.reqStr(op, "new_name");
                gh.symbol.setName(newName, SourceType.USER_DEFINED);
                Map<String, Object> inv = new LinkedHashMap<>();
                inv.put("op", "rename_global");
                inv.put("target", gh.address.toString());
                inv.put("new_name", oldName);
                String fnHint = ApiError.optStr(op, "function");
                if (fnHint != null) inv.put("function", fnHint);
                yield inv;
            }
            case "set_global_type" -> {
                GlobalHandle gh = resolveGlobal(ApiError.reqStr(op, "target"));
                Data data = p.getListing().getDefinedDataAt(gh.address);
                if (data == null) {
                    throw new ApiError("GLOBAL_DATA_NOT_DEFINED", "Global data not defined at " + gh.address, null);
                }
                String oldPath = data.getDataType().getPathName();
                int oldLen = data.getLength();
                int allowedLen = op.get("allowed_length") instanceof Number n ? n.intValue() : oldLen;
                DataType newType = parseType(ApiError.reqStr(op, "type"));
                int newLen = newType.getLength();
                if (newLen <= 0 || newLen > allowedLen) {
                    throw new ApiError("UNSAFE_GLOBAL_TYPE",
                            "Type size " + newLen + " invalid or exceeds allowed size " + allowedLen, null);
                }
                Map<CommentType, String> savedComments = captureComments(data);
                Address end = gh.address.add(Math.max(oldLen, newLen) - 1L);
                p.getListing().clearCodeUnits(gh.address, end, false);
                Data newData = p.getListing().createData(gh.address, newType);
                for (Map.Entry<CommentType, String> ce : savedComments.entrySet()) {
                    newData.setComment(ce.getKey(), ce.getValue());
                }
                Map<String, Object> inv = new LinkedHashMap<>();
                inv.put("op", "set_global_type");
                inv.put("target", gh.address.toString());
                inv.put("type", oldPath);
                inv.put("allowed_length", allowedLen);
                String fnHint = ApiError.optStr(op, "function");
                if (fnHint != null) inv.put("function", fnHint);
                yield inv;
            }
            case "set_signature" -> {
                Function fn = ws.resolveFunction(ApiError.reqStr(op, "target"));
                String oldSig = fn.getPrototypeString(false, true);
                String newSig = ApiError.reqStr(op, "signature");
                FunctionSignatureParser parser = new FunctionSignatureParser(p.getDataTypeManager(), null);
                FunctionDefinition def = parser.parse((FunctionSignature) fn.getSignature(), newSig);
                List<Variable> params = new ArrayList<>();
                for (ParameterDefinition pd : def.getArguments()) {
                    params.add(new ParameterImpl(pd.getName(), pd.getDataType(), p, SourceType.USER_DEFINED));
                }
                fn.setReturnType(def.getReturnType(), SourceType.USER_DEFINED);
                fn.updateFunction(null, null, params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
                if (def.getName() != null && !def.getName().isBlank() && !def.getName().equals(fn.getName())) {
                    fn.setName(def.getName(), SourceType.USER_DEFINED);
                }
                liveHfCache.remove(fn.getEntryPoint().toString());
                yield Map.of("op", "set_signature", "target", fn.getEntryPoint().toString(),
                        "signature", oldSig);
            }
            case "set_comment" -> applyComment(op, liveHfCache, varRenameAliases);
            case "remove_type" -> {
                String path = ApiError.reqStr(op, "path");
                DataType dt = p.getDataTypeManager().getDataType(path);
                if (dt != null) p.getDataTypeManager().remove(dt);
                yield null;
            }
            default -> throw new ApiError("INVALID_ARGUMENT", "Unsupported edit op: " + kind, null);
        };
    }

    private Map<String, Object> applyComment(
            Map<String, Object> op,
            Map<String, HighFunction> liveHfCache,
            Map<String, Map<String, String>> varRenameAliases) throws Exception {
        String ctype = ApiError.optStr(op, "comment_type");
        if (ctype == null) ctype = "function";
        String target = ApiError.reqStr(op, "target");
        String text = ApiError.reqRawStr(op, "text");
        String normalizedText = text.isEmpty() ? null : text;

        if ("var".equals(ctype)) {
            Function fn = ws.resolveFunction(target);
            String fnAddr = fn.getEntryPoint().toString();
            String requestedVar = ApiError.reqStr(op, "var_name");
            String effectiveVar = varRenameAliases.getOrDefault(fnAddr, Map.of()).getOrDefault(requestedVar, requestedVar);
            VarHandle vh = resolveVar(fn, effectiveVar, liveHfCache);
            String old = vh.comment();
            vh.setComment(normalizedText);
            liveHfCache.remove(fnAddr);
            return Map.of("op", "set_comment", "comment_type", "var", "target", fnAddr,
                    "var_name", vh.name(), "text", old == null ? "" : old);
        }
        if ("function".equals(ctype) || "plate".equals(ctype)) {
            Function fn = ws.resolveFunction(target);
            String old = fn.getComment();
            fn.setComment(normalizedText);
            return Map.of("op", "set_comment", "comment_type", ctype, "target", fn.getEntryPoint().toString(),
                    "text", old == null ? "" : old);
        }
        CommentType ghidraType = switch (ctype) {
            case "pre" -> CommentType.PRE;
            case "eol" -> CommentType.EOL;
            default -> throw new ApiError("INVALID_ARGUMENT",
                    "comment_type must be function, plate, pre, eol, or var", null);
        };
        Address addr = ws.parseAddress(target);
        if (addr == null) throw new ApiError("INVALID_ARGUMENT", "Invalid address for comment: " + target, null);
        CodeUnit cu = ws.program().getListing().getCodeUnitAt(addr);
        if (cu == null) throw new ApiError("NOT_FOUND", "No code unit at " + addr, null);
        String old = cu.getComment(ghidraType);
        cu.setComment(ghidraType, normalizedText);
        return Map.of("op", "set_comment", "comment_type", ctype, "target", addr.toString(),
                "text", old == null ? "" : old);
    }

    private VarHandle resolveVar(Function fn, String varName, Map<String, HighFunction> cache) throws Exception {
        for (Variable v : fn.getAllVariables()) {
            if (v.getName().equals(varName)) return new DbVarHandle(v);
        }
        String fnAddr = fn.getEntryPoint().toString();
        HighFunction hf = cache.get(fnAddr);
        if (hf == null) {
            var d = ws.decompileFresh(fn, DECOMPILE_TIMEOUT_SEC);
            if ("complete".equals(d.status()) && d.highFunction() != null) {
                hf = d.highFunction();
                cache.put(fnAddr, hf);
            }
        }
        if (hf != null && hf.getLocalSymbolMap() != null) {
            Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol hs = it.next();
                if (!hs.isGlobal() && hs.getName().equals(varName)) {
                    return new HighVarHandle(fn, hs);
                }
            }
        }
        throw new ApiError("VARIABLE_NOT_FOUND", "Variable '" + varName + "' not found in " + fn.getName(), null);
    }

    private GlobalHandle resolveGlobal(String target) {
        Program p = ws.program();
        Address addr = ws.parseAddress(target);
        if (addr != null) {
            Symbol sym = p.getSymbolTable().getPrimarySymbol(addr);
            if (sym != null && sym.isGlobal()) return new GlobalHandle(sym, addr);
        }
        List<Symbol> found = p.getSymbolTable().getGlobalSymbols(target);
        if (found.size() == 1) return new GlobalHandle(found.getFirst(), found.getFirst().getAddress());
        if (found.size() > 1) {
            throw new ApiError("AMBIGUOUS_TARGET", "Multiple globals named " + target + "; pass address", null);
        }
        throw new ApiError("GLOBAL_NOT_FOUND", "Global symbol not found: " + target, null);
    }

    private DataType parseType(String typeSpec) throws Exception {
        DataTypeManager dtm = ws.program().getDataTypeManager();
        DataType direct = dtm.getDataType(typeSpec);
        if (direct != null) return direct;
        return new DataTypeParser(null, dtm, null, DataTypeParser.AllowedDataTypes.ALL).parse(typeSpec);
    }

    private static Map<CommentType, String> captureComments(Data data) {
        Map<CommentType, String> map = new EnumMap<>(CommentType.class);
        for (CommentType ct : CommentType.values()) {
            String c = data.getComment(ct);
            if (c != null) map.put(ct, c);
        }
        return map;
    }

    private static void requireWrite(ApiError.AccessMode mode) {
        if (mode != ApiError.AccessMode.READ_WRITE) {
            throw new ApiError("READ_ONLY", "Write operations are forbidden on read-only endpoints", null);
        }
    }

    private record GlobalHandle(Symbol symbol, Address address) {}

    private interface VarHandle {
        String name();
        String dataTypePath();
        String comment();
        void rename(String newName) throws Exception;
        void setType(DataType dt) throws Exception;
        void setComment(String text) throws Exception;
    }

    private record DbVarHandle(Variable v) implements VarHandle {
        @Override public String name() { return v.getName(); }
        @Override public String dataTypePath() { return v.getDataType().getPathName(); }
        @Override public String comment() { return v.getComment(); }
        @Override public void rename(String newName) throws Exception { v.setName(newName, SourceType.USER_DEFINED); }
        @Override public void setType(DataType dt) throws Exception { v.setDataType(dt, SourceType.USER_DEFINED); }
        @Override public void setComment(String text) { v.setComment(text); }
    }

    private static final class HighVarHandle implements VarHandle {
        private final Function fn;
        private final HighSymbol hs;

        HighVarHandle(Function fn, HighSymbol hs) {
            this.fn = fn;
            this.hs = hs;
        }

        @Override public String name() { return hs.getName(); }
        @Override public String dataTypePath() { return hs.getDataType().getPathName(); }

        @Override
        public String comment() {
            Variable v = HighFunctionDBUtil.getFunctionVariable(hs);
            return v == null ? null : v.getComment();
        }

        @Override
        public void rename(String newName) throws Exception {
            HighFunctionDBUtil.updateDBVariable(hs, newName, null, SourceType.USER_DEFINED);
        }

        @Override
        public void setType(DataType dt) throws Exception {
            HighFunctionDBUtil.updateDBVariable(hs, null, dt, SourceType.USER_DEFINED);
        }

        @Override
        public void setComment(String text) throws Exception {
            Variable v = HighFunctionDBUtil.getFunctionVariable(hs);
            if (v == null) {
                HighFunctionDBUtil.updateDBVariable(hs, hs.getName(), hs.getDataType(), SourceType.USER_DEFINED);
                for (Variable cand : fn.getAllVariables()) {
                    if (cand.getName().equals(hs.getName())) { v = cand; break; }
                }
            }
            if (v == null) throw new ApiError("VARIABLE_NOT_FOUND", "Could not materialize DB variable for " + hs.getName(), null);
            v.setComment(text);
        }
    }
}
