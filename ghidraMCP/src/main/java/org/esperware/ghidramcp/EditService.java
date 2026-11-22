package org.esperware.ghidramcp;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
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
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Write-enabled mutation service enforcing AccessMode, CAS version checks, transactions, and inverse ops. */
final class EditService {
    private static final int DECOMPILE_TIMEOUT_SEC = 30;
    private static final int MAX_BATCH_OPS = 50;
    private static final int MAX_AUTO_GLOBAL_REFS = 10;
    private static final Pattern SIG_NAME_PATTERN = Pattern.compile("^(.*?)\\b([A-Za-z_][A-Za-z0-9_]*)$");

    private static final class AddTypesOnly extends DataTypeConflictHandler {
        private final Set<String> existingPaths;

        AddTypesOnly(Set<String> existingPaths) {
            this.existingPaths = existingPaths;
        }

        @Override
        public ConflictResult resolveConflict(DataType added, DataType existing) {
            if (existingPaths.contains(existing.getPathName())) {
                throw new ApiError("TYPE_EXISTS", "Type already exists: " + existing.getPathName(), null);
            }
            return ConflictResult.USE_EXISTING;
        }

        @Override
        public boolean shouldUpdate(DataType source, DataType existing) {
            return false;
        }

        @Override
        public DataTypeConflictHandler getSubsequentHandler() {
            return this;
        }
    }

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
        for (Map<String, Object> op : edits) {
            String kind = ApiError.reqStr(op, "op");
            if (List.of("remove_type", "delete_function", "clear_data").contains(kind)) {
                throw new ApiError("INVALID_ARGUMENT", "Unsupported edit op: " + kind, null);
            }
        }

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

                CategoryPath cat = new CategoryPath(categoryPath);
                try (var tx = tempDtm.openTransaction("Set declaration category")) {
                    for (DataType dt : parsedTypes) {
                        if (dt.getDataTypeManager() == tempDtm) dt.setCategoryPath(cat);
                    }
                }
                List<Map<String, Object>> defined = new ArrayList<>();
                List<Map<String, Object>> inverseOps = new ArrayList<>();
                try {
                    return ws.runEdit(() -> {
                        Set<String> existingPaths = new HashSet<>();
                        targetDtm.getAllDataTypes().forEachRemaining(dt -> existingPaths.add(dt.getPathName()));
                        var conflicts = new AddTypesOnly(existingPaths);
                        for (DataType dt : parsedTypes) {
                            DataType candidate = dt;
                            if (dt.getDataTypeManager() != tempDtm) {
                                candidate = dt.copy(targetDtm);
                                candidate.setCategoryPath(cat);
                            }
                            String destPath = candidate.getPathName();
                            if (existingPaths.contains(destPath)) {
                                throw new ApiError("TYPE_EXISTS", "Type already exists: " + destPath, current);
                            }
                            DataType resolved = targetDtm.resolve(candidate, conflicts);
                            defined.add(Map.of(
                                    "name", resolved.getName(),
                                    "path", resolved.getPathName(),
                                    "size", resolved.getLength()));
                        }
                        targetDtm.getAllDataTypes().forEachRemaining(dt -> {
                            if (!existingPaths.contains(dt.getPathName())) {
                                inverseOps.add(Map.of("op", "remove_type", "path", dt.getPathName()));
                            }
                        });
                        Collections.reverse(inverseOps);
                        ws.invalidateCache();
                        long newVer = persistVersion(actor, "define_type", reason,
                                List.of(Map.of("op", "define_type", "category", categoryPath, "c_declaration", cDecl)),
                                inverseOps, List.of());
                        return Map.of("ok", true, "version", newVer, "previous_version", current, "defined_types", defined);
                    });
                } catch (ApiError err) {
                    throw new ApiError(err.code, err.getMessage(), current);
                } catch (Exception ex) {
                    throw new ApiError("EDIT_FAILED",
                            ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage(), current);
                }
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
        long current = store.currentVersion();
        try {
            return ws.runEdit(() -> applyAndRecordBatch(operation, actor, reason, ops, current));
        } catch (ApiError err) {
            throw new ApiError(err.code, err.getMessage(), current);
        } catch (Exception ex) {
            throw new ApiError("EDIT_FAILED",
                    ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage(), current);
        }
    }

    private Map<String, Object> applyAndRecordBatch(
            String operation, String actor, String reason, List<Map<String, Object>> ops, long current)
            throws Exception {
        Program p = ws.program();
        PreResolution pre = preResolveTouchedFunctions(ops);
        Map<String, String> beforeCode = new LinkedHashMap<>();
        Map<String, String> beforeNames = new HashMap<>();
        for (Map.Entry<String, Function> e : pre.touchedFunctions.entrySet()) {
            beforeNames.put(e.getKey(), e.getValue().getName());
            var d = ws.decompileCached(e.getValue(), DECOMPILE_TIMEOUT_SEC);
            beforeCode.put(e.getKey(), "complete".equals(d.status()) ? d.code() : null);
        }

        Map<String, HighFunction> liveHfCache = new HashMap<>();
        Map<String, Map<String, String>> varRenameAliases = new HashMap<>();
        List<List<Map<String, Object>>> perOpInverses = new ArrayList<>();
        for (Map<String, Object> op : ops) {
            List<Map<String, Object>> inv = applyOp(op, liveHfCache, varRenameAliases);
            if (inv != null && !inv.isEmpty()) perOpInverses.add(inv);
            if ("revert".equals(operation)) varRenameAliases.clear();
        }

        ws.invalidateCache();

        for (String createdAddrStr : pre.pendingCreatedAddrs) {
            Address createdAddr = ws.parseAddress(createdAddrStr);
            if (createdAddr != null) {
                Function createdFn = p.getFunctionManager().getFunctionAt(createdAddr);
                if (createdFn != null) pre.touchedFunctions.putIfAbsent(createdAddrStr, createdFn);
            }
        }

        List<VersionStore.FunctionDiff> storedDiffs = new ArrayList<>();
        List<Map<String, Object>> apiDiffs = new ArrayList<>();
        for (Map.Entry<String, Function> e : pre.touchedFunctions.entrySet()) {
            String addr = e.getKey();
            Address entryAddr = ws.parseAddress(addr);
            Function liveFn = entryAddr == null ? null : p.getFunctionManager().getFunctionAt(entryAddr);
            String before = beforeCode.get(addr);

            if (liveFn == null) {
                String delName = beforeNames.get(addr);
                String diff = before != null ? ApiError.unifiedDiff(delName + " @ " + addr, before, "") : "";
                storedDiffs.add(new VersionStore.FunctionDiff(addr, delName, before, "", diff, "deleted"));

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("function_address", addr);
                entry.put("function_name", delName);
                entry.put("decompile_status", "deleted");
                entry.put("diff", diff);
                entry.put("variables", List.of());
                apiDiffs.add(entry);
                continue;
            }

            ProgramWorkspace.LiveDecompile after = ws.decompileFresh(liveFn, DECOMPILE_TIMEOUT_SEC);
            String afterText = "complete".equals(after.status()) ? after.code() : null;
            String effectiveBefore = before != null ? before : (pre.pendingCreatedAddrs.contains(addr) ? "" : null);
            String diff = (effectiveBefore != null && afterText != null)
                    ? ApiError.unifiedDiff(liveFn.getName() + " @ " + addr, effectiveBefore, afterText)
                    : "";
            storedDiffs.add(new VersionStore.FunctionDiff(addr, liveFn.getName(), effectiveBefore, afterText, diff, after.status()));

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("function_address", addr);
            entry.put("function_name", liveFn.getName());
            entry.put("decompile_status", after.status());
            if (after.error() != null) entry.put("decompile_error", after.error());
            entry.put("diff", diff);
            entry.put("variables", ws.extractVariables(liveFn, after.highFunction()));
            apiDiffs.add(entry);
        }

        List<Map<String, Object>> inverseOps = new ArrayList<>();
        Collections.reverse(perOpInverses);
        for (List<Map<String, Object>> group : perOpInverses) {
            inverseOps.addAll(group);
        }
        long newVersion = persistVersion(actor, operation, reason, ops, inverseOps, storedDiffs);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("version", newVersion);
        out.put("previous_version", current);
        out.put("diffs", apiDiffs);
        return out;
    }

    private long persistVersion(String actor, String operation, String reason, List<Map<String, Object>> ops,
                                List<Map<String, Object>> inverseOps, List<VersionStore.FunctionDiff> diffs)
            throws Exception {
        ws.checkEditTransaction();
        long version = store.recordVersion(actor, operation, reason, ops, inverseOps, diffs, ws::saveVersion);
        ws.versionPublished();
        return version;
    }

    private PreResolution preResolveTouchedFunctions(List<Map<String, Object>> ops) {
        Program p = ws.program();
        PreResolution pre = new PreResolution();
        for (Map<String, Object> op : ops) {
            String kind = ApiError.reqStr(op, "op");
            switch (kind) {
                case "create_function" -> {
                    Address addr = ws.parseAddress(ApiError.reqStr(op, "target"));
                    if (addr == null) throw new ApiError("INVALID_ARGUMENT", "Invalid address for create_function", null);
                    String addrKey = addr.toString();
                    pre.pendingCreatedAddrs.add(addrKey);
                    String name = ApiError.optStr(op, "name");
                    if (name != null) pre.pendingCreatedNames.put(name.toLowerCase(Locale.ROOT), addrKey);
                }
                case "rename_function" -> {
                    String target = ApiError.reqStr(op, "target");
                    String newName = ApiError.reqStr(op, "new_name");
                    Function fn = resolvePreFunction(target, pre);
                    if (fn != null) {
                        pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                        pre.fnAliases.put(newName.toLowerCase(Locale.ROOT), fn);
                    } else {
                        String pending = pendingCreatedAddr(target, pre);
                        if (pending != null) pre.pendingCreatedNames.put(newName.toLowerCase(Locale.ROOT), pending);
                    }
                }
                case "set_signature" -> {
                    String target = ApiError.reqStr(op, "target");
                    String sig = ApiError.reqStr(op, "signature");
                    Function fn = resolvePreFunction(target, pre);
                    if (fn != null) pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                    String sigName = extractSignatureName(sig);
                    if (sigName != null) {
                        if (fn != null) pre.fnAliases.put(sigName.toLowerCase(Locale.ROOT), fn);
                        else {
                            String pending = pendingCreatedAddr(target, pre);
                            if (pending != null) pre.pendingCreatedNames.put(sigName.toLowerCase(Locale.ROOT), pending);
                        }
                    }
                }
                case "rename_var", "set_var_type" -> {
                    Function fn = resolvePreFunction(ApiError.reqStr(op, "function"), pre);
                    if (fn != null) pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                }
                case "delete_function" -> {
                    Function fn = resolvePreFunction(ApiError.reqStr(op, "target"), pre);
                    if (fn != null) pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                }
                case "set_comment" -> {
                    String ctype = ApiError.optStr(op, "comment_type");
                    String target = ApiError.reqStr(op, "target");
                    if ("var".equals(ctype) || "function".equals(ctype) || "plate".equals(ctype) || ctype == null) {
                        Function fn = resolvePreFunction(target, pre);
                        if (fn != null) pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                    } else {
                        Address a = ws.parseAddress(target);
                        Function fn = a == null ? null : p.getFunctionManager().getFunctionContaining(a);
                        if (fn != null) pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                    }
                }
                case "rename_global", "set_global_type" -> {
                    String target = ApiError.reqStr(op, "target");
                    Address gAddr = resolveGlobalAddrForPre(target, pre);
                    if ("rename_global".equals(kind) && gAddr != null) {
                        String newName = ApiError.reqStr(op, "new_name");
                        pre.globalAliases.put(newName.toLowerCase(Locale.ROOT), gAddr);
                    }
                    String fnHint = ApiError.optStr(op, "function");
                    if (fnHint != null) {
                        Function fn = resolvePreFunction(fnHint, pre);
                        if (fn != null) pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                    } else if (gAddr != null) {
                        Address scanEnd = computeGlobalScanEnd(p, gAddr, kind, op);
                        addReferencingFunctions(p, gAddr, scanEnd, pre.touchedFunctions, MAX_AUTO_GLOBAL_REFS);
                    }
                }
                case "remove_type", "clear_data" -> {
                    String fnHint = ApiError.optStr(op, "function");
                    if (fnHint != null) {
                        Function fn = resolvePreFunction(fnHint, pre);
                        if (fn != null) pre.touchedFunctions.putIfAbsent(fn.getEntryPoint().toString(), fn);
                    }
                }
                default -> throw new ApiError("INVALID_ARGUMENT", "Unsupported edit op: " + kind, null);
            }
        }
        return pre;
    }

    private Function resolvePreFunction(String target, PreResolution pre) {
        Program p = ws.program();
        Address addr = ws.parseAddress(target);
        if (addr != null) {
            if (pre.pendingCreatedAddrs.contains(addr.toString())) return null;
            Function exact = p.getFunctionManager().getFunctionAt(addr);
            if (exact != null) return exact;
            Function containing = p.getFunctionManager().getFunctionContaining(addr);
            if (containing != null) return containing;
            return ws.resolveFunction(target);
        }
        String key = target.trim().toLowerCase(Locale.ROOT);
        if (pre.fnAliases.containsKey(key)) return pre.fnAliases.get(key);
        if (pre.pendingCreatedNames.containsKey(key)) return null;
        return ws.resolveFunction(target);
    }

    private String pendingCreatedAddr(String target, PreResolution pre) {
        Address addr = ws.parseAddress(target);
        if (addr != null && pre.pendingCreatedAddrs.contains(addr.toString())) {
            return addr.toString();
        }
        return pre.pendingCreatedNames.get(target.trim().toLowerCase(Locale.ROOT));
    }

    private static String extractSignatureName(String sig) {
        int paren = sig.indexOf('(');
        if (paren <= 0) return null;
        String head = sig.substring(0, paren).stripTrailing();
        Matcher m = SIG_NAME_PATTERN.matcher(head);
        if (!m.matches() || m.group(1).isBlank()) return null;
        return m.group(2);
    }

    private Address resolveGlobalAddrForPre(String target, PreResolution pre) {
        Address addr = ws.parseAddress(target);
        if (addr != null) return addr;
        Address aliased = pre.globalAliases.get(target.trim().toLowerCase(Locale.ROOT));
        if (aliased != null) return aliased;
        List<Symbol> found = ws.program().getSymbolTable().getGlobalSymbols(target.trim());
        return found.size() == 1 ? found.getFirst().getAddress() : null;
    }

    private Address computeGlobalScanEnd(Program p, Address start, String kind, Map<String, Object> op) {
        Address scanEnd = start;
        Data existing = p.getListing().getDefinedDataAt(start);
        if (existing != null && existing.getMaxAddress().compareTo(scanEnd) > 0) {
            scanEnd = existing.getMaxAddress();
        }
        if ("set_global_type".equals(kind)) {
            String typeSpec = ApiError.optStr(op, "type");
            if (typeSpec != null) {
                try {
                    DataType dt = parseType(typeSpec);
                    if (dt.getLength() > 0) {
                        Address end = start.addNoWrap(dt.getLength() - 1L);
                        if (end.compareTo(scanEnd) > 0) scanEnd = end;
                    }
                } catch (Exception ignored) {
                }
            }
        }
        return scanEnd;
    }

    private static void addReferencingFunctions(
            Program p,
            Address start,
            Address end,
            Map<String, Function> touchedFunctions,
            int maxFuncs) {
        var refMgr = p.getReferenceManager();
        var destIt = refMgr.getReferenceDestinationIterator(new AddressSet(start, end), true);
        int added = 0;
        while (destIt.hasNext() && added < maxFuncs) {
            Address dest = destIt.next();
            ReferenceIterator refs = refMgr.getReferencesTo(dest);
            while (refs.hasNext() && added < maxFuncs) {
                Reference ref = refs.next();
                Function refFn = p.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (refFn != null && touchedFunctions.putIfAbsent(refFn.getEntryPoint().toString(), refFn) == null) {
                    added++;
                }
            }
        }
    }

    private List<Map<String, Object>> applyOp(
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
                yield List.of(Map.of("op", "rename_function", "target", fn.getEntryPoint().toString(), "new_name", oldName));
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
                var aliases = varRenameAliases.computeIfAbsent(fnAddr, k -> new HashMap<>());
                aliases.replaceAll((alias, name) -> name.equals(oldName) ? newName : name);
                aliases.put(oldName, newName);
                aliases.put(newName, newName);
                liveHfCache.remove(fnAddr);
                yield List.of(Map.of("op", "rename_var", "function", fnAddr, "var_name", newName, "new_name", oldName));
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
                yield List.of(Map.of("op", "set_var_type", "function", fnAddr, "var_name", vh.name(), "type", oldPath));
            }
            case "rename_global" -> List.of(renameGlobalOp(op));
            case "set_global_type" -> setGlobalTypeOp(op);
            case "clear_data" -> clearDataOp(op);
            case "set_signature" -> List.of(setSignatureOp(op, liveHfCache));
            case "create_function" -> createFunctionOp(op);
            case "delete_function" -> deleteFunctionOp(op, liveHfCache);
            case "set_comment" -> List.of(applyComment(op, liveHfCache, varRenameAliases));
            case "remove_type" -> {
                String path = ApiError.reqStr(op, "path");
                DataType dt = p.getDataTypeManager().getDataType(path);
                if (dt != null && !p.getDataTypeManager().remove(dt)) {
                    throw new ApiError("EDIT_FAILED", "Could not remove type " + path, null);
                }
                yield List.of();
            }
            default -> throw new ApiError("INVALID_ARGUMENT", "Unsupported edit op: " + kind, null);
        };
    }

    private Map<String, Object> renameGlobalOp(Map<String, Object> op) throws Exception {
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
        return inv;
    }

    private List<Map<String, Object>> setGlobalTypeOp(Map<String, Object> op) throws Exception {
        Program p = ws.program();
        String target = ApiError.reqStr(op, "target");
        Address addr = null;
        if (ProgramWorkspace.hasExplicitAddressPrefix(target)) {
            addr = ws.parseAddress(target);
        } else {
            List<Symbol> found = p.getSymbolTable().getGlobalSymbols(target.trim());
            if (found.size() == 1) addr = found.getFirst().getAddress();
            else if (found.size() > 1) {
                throw new ApiError("AMBIGUOUS_TARGET", "Multiple globals named " + target + "; pass address", null);
            } else {
                addr = ws.parseAddress(target);
            }
        }
        if (addr == null) addr = resolveGlobal(target).address;

        DataType newType = parseType(ApiError.reqStr(op, "type"));
        int explicitLen = op.get("length") == null ? 0 : ApiError.optInt(op, "length", 0, 1, 1_048_576);
        int newLen = newType.getLength() > 0 ? newType.getLength() : explicitLen;
        if (newLen <= 0) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE", "Global data type must have fixed positive size", null);
        }

        Address end;
        try {
            end = addr.addNoWrap(newLen - 1L);
        } catch (AddressOverflowException ex) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE", "Type extends past end of address space", null);
        }

        MemoryBlock block = p.getMemory().getBlock(addr);
        if (block == null || !block.contains(end) || block.isExecute()) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE",
                    "Target range [" + addr + ".." + end + "] is not within non-executable memory", null);
        }
        if (p.getListing().getInstructions(new AddressSet(addr, end), true).hasNext()) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE",
                    "Target range [" + addr + ".." + end + "] contains decoded instructions", null);
        }

        Data containing = p.getListing().getDefinedDataContaining(addr);
        if (containing != null && !containing.getAddress().equals(addr)) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE",
                    "Address " + addr + " is inside existing data unit at " + containing.getAddress()
                            + "; target the base address instead", null);
        }

        Data existingAtStart = p.getListing().getDefinedDataAt(addr);
        boolean allowResize = ApiError.optBool(op, "allow_resize", false);
        if (!allowResize) {
            if (existingAtStart != null && newLen > existingAtStart.getLength()) {
                throw new ApiError("UNSAFE_GLOBAL_TYPE",
                        "Type size " + newLen + " exceeds existing data size " + existingAtStart.getLength()
                                + " at " + addr + "; pass allow_resize=true to replace overlapping data units", null);
            }
            if (existingAtStart == null && p.getListing().getDefinedData(new AddressSet(addr, end), true).hasNext()) {
                throw new ApiError("UNSAFE_GLOBAL_TYPE",
                        "Type overlaps existing defined data; pass allow_resize=true to replace", null);
            }
        }

        Address clearEnd = end;
        if (existingAtStart != null && existingAtStart.getMaxAddress().compareTo(clearEnd) > 0) {
            clearEnd = existingAtStart.getMaxAddress();
        }
        Data tail = p.getListing().getDefinedDataContaining(clearEnd);
        if (tail != null && tail.getMaxAddress().compareTo(clearEnd) > 0) {
            clearEnd = tail.getMaxAddress();
        }

        List<CapturedData> priorUnits = captureDataUnitsInRange(p, addr, clearEnd);
        Map<CommentType, String> preservedStartComments = existingAtStart != null ? captureComments(existingAtStart) : Map.of();

        p.getListing().clearCodeUnits(addr, clearEnd, false);
        Data newData = newType.getLength() > 0
                ? p.getListing().createData(addr, newType)
                : p.getListing().createData(addr, newType, newLen);
        applyCommentsToData(newData, preservedStartComments, op.get("comments"));

        String fnHint = ApiError.optStr(op, "function");
        long clearLen = clearEnd.subtract(addr) + 1L;
        List<Map<String, Object>> inv = new ArrayList<>();
        Map<String, Object> clearInv = new LinkedHashMap<>();
        clearInv.put("op", "clear_data");
        clearInv.put("target", addr.toString());
        clearInv.put("length", clearLen);
        if (fnHint != null) clearInv.put("function", fnHint);
        inv.add(clearInv);
        for (CapturedData cd : priorUnits) {
            inv.add(cd.toRestoreOp(fnHint));
        }
        return inv;
    }

    private List<Map<String, Object>> clearDataOp(Map<String, Object> op) throws Exception {
        Program p = ws.program();
        String target = ApiError.reqStr(op, "target");
        Address addr = ws.parseAddress(target);
        if (addr == null) throw new ApiError("INVALID_ARGUMENT", "Invalid address for clear_data: " + target, null);
        long len = ApiError.reqLong(op, "length", null);
        if (len <= 0) throw new ApiError("INVALID_ARGUMENT", "length must be positive", null);

        Address end;
        try {
            end = addr.addNoWrap(len - 1L);
        } catch (AddressOverflowException ex) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE", "clear_data extends past address space", null);
        }
        MemoryBlock block = p.getMemory().getBlock(addr);
        if (block == null || !block.contains(end) || block.isExecute()) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE", "clear_data target must be in non-executable memory", null);
        }
        if (p.getListing().getInstructions(new AddressSet(addr, end), true).hasNext()) {
            throw new ApiError("UNSAFE_GLOBAL_TYPE", "clear_data range contains decoded instructions", null);
        }

        List<CapturedData> priorUnits = captureDataUnitsInRange(p, addr, end);
        p.getListing().clearCodeUnits(addr, end, false);
        String fnHint = ApiError.optStr(op, "function");
        List<Map<String, Object>> inv = new ArrayList<>(priorUnits.size());
        for (CapturedData cd : priorUnits) {
            inv.add(cd.toRestoreOp(fnHint));
        }
        return inv;
    }

    private Map<String, Object> setSignatureOp(Map<String, Object> op, Map<String, HighFunction> liveHfCache) throws Exception {
        Program p = ws.program();
        Function fn = ws.resolveFunction(ApiError.reqStr(op, "target"));
        String oldSig = fn.getPrototypeString(false, true);
        String oldCc = fn.getCallingConventionName();
        String newSig = ApiError.reqStr(op, "signature");
        String explicitCc = ApiError.optStr(op, "calling_convention");

        FunctionSignatureParser parser = new FunctionSignatureParser(p.getDataTypeManager(), null);
        FunctionDefinition def = parser.parse((FunctionSignature) fn.getSignature(), newSig);
        List<Variable> params = new ArrayList<>();
        for (ParameterDefinition pd : def.getArguments()) {
            params.add(new ParameterImpl(pd.getName(), pd.getDataType(), p, SourceType.USER_DEFINED));
        }

        String parsedCc = def.getCallingConventionName();
        String targetCc;
        if (explicitCc != null) {
            targetCc = explicitCc;
        } else if (parsedCc != null && !parsedCc.isBlank()
                && !Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(parsedCc)) {
            targetCc = parsedCc;
        } else if (fn.hasUnknownCallingConventionName()) {
            targetCc = Function.DEFAULT_CALLING_CONVENTION_STRING;
        } else {
            targetCc = null;
        }

        fn.setReturnType(def.getReturnType(), SourceType.USER_DEFINED);
        fn.updateFunction(targetCc, null, params,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        fn.setVarArgs(def.hasVarArgs());
        if (def.getName() != null && !def.getName().isBlank() && !def.getName().equals(fn.getName())) {
            fn.setName(def.getName(), SourceType.USER_DEFINED);
        }
        liveHfCache.remove(fn.getEntryPoint().toString());
        return Map.of(
                "op", "set_signature",
                "target", fn.getEntryPoint().toString(),
                "signature", oldSig,
                "calling_convention", oldCc == null ? Function.UNKNOWN_CALLING_CONVENTION_STRING : oldCc);
    }

    private List<Map<String, Object>> createFunctionOp(Map<String, Object> op) {
        Program p = ws.program();
        String target = ApiError.reqStr(op, "target");
        Address addr = ws.parseAddress(target);
        if (addr == null) throw new ApiError("INVALID_ARGUMENT", "Invalid address for create_function: " + target, null);
        String name = ApiError.optStr(op, "name");

        MemoryBlock block = p.getMemory().getBlock(addr);
        if (block == null || !block.isExecute()) {
            throw new ApiError("INVALID_ARGUMENT", "Address " + addr + " is not in executable memory", null);
        }
        if (p.getFunctionManager().getFunctionAt(addr) != null) {
            throw new ApiError("FUNCTION_EXISTS", "Function already exists at " + addr, null);
        }
        Function containing = p.getFunctionManager().getFunctionContaining(addr);
        if (containing != null) {
            throw new ApiError("INVALID_ARGUMENT",
                    "Address " + addr + " is already inside function " + containing.getName() + " @ " + containing.getEntryPoint(), null);
        }

        if (p.getListing().getInstructionAt(addr) == null) {
            DisassembleCommand dis = new DisassembleCommand(addr, null, true);
            dis.enableCodeAnalysis(false);
            dis.applyTo(p, TaskMonitor.DUMMY);
            if (p.getListing().getInstructionAt(addr) == null) {
                throw new ApiError("EDIT_FAILED", "No valid instruction to disassemble at " + addr, null);
            }
        }

        SourceType src = name != null ? SourceType.USER_DEFINED : SourceType.ANALYSIS;
        CreateFunctionCmd cmd = new CreateFunctionCmd(name, addr, null, src);
        boolean ok = cmd.applyTo(p, TaskMonitor.DUMMY);
        Function created = cmd.getFunction() != null ? cmd.getFunction() : p.getFunctionManager().getFunctionAt(addr);
        if (!ok || created == null) {
            String detail = cmd.getStatusMsg() != null ? ": " + cmd.getStatusMsg() : "";
            throw new ApiError("EDIT_FAILED", "Could not create function at " + addr + detail, null);
        }
        return List.of(Map.of("op", "delete_function", "target", addr.toString()));
    }

    private List<Map<String, Object>> deleteFunctionOp(Map<String, Object> op, Map<String, HighFunction> liveHfCache) {
        Program p = ws.program();
        Function fn = ws.resolveFunction(ApiError.reqStr(op, "target"));
        Address entry = fn.getEntryPoint();
        String oldName = fn.getSymbol().getSource() == SourceType.USER_DEFINED ? fn.getName() : null;

        DeleteFunctionCmd cmd = new DeleteFunctionCmd(entry);
        if (!cmd.applyTo(p) || p.getFunctionManager().getFunctionAt(entry) != null) {
            String detail = cmd.getStatusMsg() != null ? ": " + cmd.getStatusMsg() : "";
            throw new ApiError("EDIT_FAILED", "Could not delete function at " + entry + detail, null);
        }
        liveHfCache.remove(entry.toString());
        Map<String, Object> inv = new LinkedHashMap<>();
        inv.put("op", "create_function");
        inv.put("target", entry.toString());
        if (oldName != null) inv.put("name", oldName);
        return List.of(inv);
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
        String trimmed = typeSpec.trim();
        DataTypeManager dtm = ws.program().getDataTypeManager();
        DataType direct = dtm.getDataType(trimmed);
        if (direct != null) return direct;

        DataTypeParser parser = new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL);
        try {
            if (trimmed.startsWith("/")) {
                int modIdx = firstPtrOrArrayIndex(trimmed);
                String prefix = modIdx >= 0 ? trimmed.substring(0, modIdx) : trimmed;
                int slash = prefix.lastIndexOf('/');
                if (slash >= 0) {
                    String catText = slash == 0 ? "/" : prefix.substring(0, slash);
                    String rest = trimmed.substring(slash + 1).trim();
                    return parser.parse(rest, new CategoryPath(catText));
                }
            }
            return parser.parse(trimmed);
        } catch (InvalidDataTypeException ex) {
            String baseName = extractBaseTypeName(trimmed);
            if (!baseName.isEmpty()) {
                List<DataType> matches = new ArrayList<>();
                dtm.findDataTypes(baseName, matches);
                if (matches.size() > 1) {
                    List<String> paths = matches.stream().limit(5).map(DataType::getPathName).toList();
                    throw new ApiError("AMBIGUOUS_TYPE",
                            "Ambiguous data type '" + typeSpec + "'; specify full path: " + paths, null);
                }
            }
            throw new ApiError("INVALID_TYPE", ex.getMessage() == null ? "Invalid data type: " + typeSpec : ex.getMessage(), null);
        }
    }

    private static int firstPtrOrArrayIndex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '*' || ch == '[') return i;
        }
        return -1;
    }

    private static int firstModifierIndex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '*' || ch == '[' || Character.isWhitespace(ch)) return i;
        }
        return -1;
    }

    private static String extractBaseTypeName(String spec) {
        int mod = firstModifierIndex(spec);
        String base = mod >= 0 ? spec.substring(0, mod) : spec;
        int slash = base.lastIndexOf('/');
        return slash >= 0 ? base.substring(slash + 1).trim() : base.trim();
    }

    private static List<CapturedData> captureDataUnitsInRange(Program p, Address start, Address end) {
        List<CapturedData> list = new ArrayList<>();
        DataIterator it = p.getListing().getDefinedData(new AddressSet(start, end), true);
        while (it.hasNext()) {
            Data d = it.next();
            list.add(new CapturedData(
                    d.getAddress().toString(),
                    d.getDataType().getPathName(),
                    d.getLength(),
                    commentsToStringMap(captureComments(d))));
        }
        return list;
    }

    private static Map<CommentType, String> captureComments(Data data) {
        Map<CommentType, String> map = new EnumMap<>(CommentType.class);
        for (CommentType ct : CommentType.values()) {
            String c = data.getComment(ct);
            if (c != null) map.put(ct, c);
        }
        return map;
    }

    private static Map<String, String> commentsToStringMap(Map<CommentType, String> comments) {
        if (comments.isEmpty()) return Map.of();
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<CommentType, String> e : comments.entrySet()) {
            out.put(e.getKey().name(), e.getValue());
        }
        return out;
    }

    private static void applyCommentsToData(Data data, Map<CommentType, String> captured, Object opCommentsObj) {
        for (Map.Entry<CommentType, String> ce : captured.entrySet()) {
            data.setComment(ce.getKey(), ce.getValue());
        }
        if (opCommentsObj instanceof Map<?, ?> rawMap) {
            for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) continue;
                try {
                    CommentType ct = CommentType.valueOf(String.valueOf(entry.getKey()));
                    data.setComment(ct, String.valueOf(entry.getValue()));
                } catch (IllegalArgumentException ignored) {
                }
            }
        }
    }

    private static void requireWrite(ApiError.AccessMode mode) {
        if (mode != ApiError.AccessMode.READ_WRITE) {
            throw new ApiError("READ_ONLY", "Write operations are forbidden on read-only endpoints", null);
        }
    }

    private record GlobalHandle(Symbol symbol, Address address) {}

    private record CapturedData(String address, String typePath, int length, Map<String, String> comments) {
        Map<String, Object> toRestoreOp(String fnHint) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("op", "set_global_type");
            m.put("target", address);
            m.put("type", typePath);
            if (length > 0) m.put("length", length);
            m.put("allow_resize", true);
            if (!comments.isEmpty()) m.put("comments", comments);
            if (fnHint != null) m.put("function", fnHint);
            return m;
        }
    }

    private static final class PreResolution {
        final Map<String, Function> touchedFunctions = new LinkedHashMap<>();
        final Map<String, Function> fnAliases = new HashMap<>();
        final Set<String> pendingCreatedAddrs = new LinkedHashSet<>();
        final Map<String, String> pendingCreatedNames = new HashMap<>();
        final Map<String, Address> globalAliases = new HashMap<>();
    }

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
