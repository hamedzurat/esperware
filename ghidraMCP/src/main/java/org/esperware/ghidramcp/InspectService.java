package org.esperware.ghidramcp;

import com.google.gson.Gson;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.task.TaskMonitor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Thread-safe read-only query service backing all 9 read MCP tools and WebUI inspection endpoints. */
final class InspectService {
    private static final int DECOMPILE_TIMEOUT_SEC = 30;
    private static final int SEARCH_DECOMPILE_TIMEOUT_SEC = 2;
    private static final int PSEUDOCODE_SLICE_CHARS = 24_000;
    private static final int MAX_LIST_LIMIT = 200;
    private static final int MAX_MEMORY_BYTES = 4096;
    private static final int TYPE_COMPONENTS_CAP = 100;

    private final ProgramWorkspace ws;
    private final VersionStore store;
    private final Gson gson = new Gson();

    private record OffsetCursor(int offset) {}

    private record SearchCursor(String query, String scope, String nextAddress, int offset) {}

    InspectService(ProgramWorkspace ws, VersionStore store) {
        this.ws = ws;
        this.store = store;
    }

    Map<String, Object> programInfo() throws Exception {
        return ws.withReadLock(() -> {
            Program p = ws.program();
            List<Map<String, Object>> segments = new ArrayList<>();
            for (MemoryBlock block : p.getMemory().getBlocks()) {
                Map<String, Object> seg = new LinkedHashMap<>();
                seg.put("name", block.getName());
                seg.put("start", block.getStart().toString());
                seg.put("end", block.getEnd().toString());
                seg.put("size", block.getSize());
                seg.put("read", block.isRead());
                seg.put("write", block.isWrite());
                seg.put("execute", block.isExecute());
                segments.add(seg);
            }
            List<String> entryPoints = new ArrayList<>();
            var entries = p.getSymbolTable().getExternalEntryPointIterator();
            while (entries.hasNext() && entryPoints.size() < 32) {
                entryPoints.add(entries.next().toString());
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("binary_name", ws.binaryName());
            out.put("binary_sha256", ws.binarySha256());
            out.put("ghidra_version", ws.ghidraVersion());
            out.put("format", p.getExecutableFormat());
            out.put("language", p.getLanguageID().getIdAsString());
            out.put("compiler", p.getCompilerSpec().getCompilerSpecID().getIdAsString());
            out.put("endian", p.getMemory().isBigEndian() ? "big" : "little");
            out.put("function_count", p.getFunctionManager().getFunctionCount());
            out.put("type_count", p.getDataTypeManager().getDataTypeCount(false));
            out.put("entry_points", entryPoints);
            out.put("segments", segments);
            return out;
        });
    }

    Map<String, Object> listFunctions(Map<String, Object> args) throws Exception {
        String filter = ApiError.optStr(args, "filter");
        String sort = ApiError.optStr(args, "sort");
        if (sort != null && !List.of("address", "name", "size").contains(sort)) {
            throw new ApiError("INVALID_ARGUMENT", "sort must be address, name, or size", null);
        }
        int limit = ApiError.optInt(args, "limit", 50, 1, MAX_LIST_LIMIT);
        OffsetCursor cursor = ApiError.decodeCursor(gson, args == null ? null : args.get("cursor"), OffsetCursor.class);
        int start = cursor == null ? 0 : Math.max(0, cursor.offset());
        String folded = filter == null ? null : filter.toLowerCase(Locale.ROOT);

        return ws.withReadLock(() -> {
            List<Function> all = new ArrayList<>();
            FunctionIterator it = ws.program().getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function fn = it.next();
                if (folded != null) {
                    String name = fn.getName().toLowerCase(Locale.ROOT);
                    String addr = fn.getEntryPoint().toString().toLowerCase(Locale.ROOT);
                    if (!name.contains(folded) && !addr.contains(folded)) continue;
                }
                all.add(fn);
            }
            if ("name".equals(sort)) {
                all.sort(Comparator.comparing(Function::getName, String.CASE_INSENSITIVE_ORDER));
            } else if ("size".equals(sort)) {
                all.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
            }
            int end = Math.min(start + limit, all.size());
            List<Map<String, Object>> page = new ArrayList<>(Math.max(0, end - start));
            for (int i = start; i < end; i++) {
                Function fn = all.get(i);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", fn.getEntryPoint().toString());
                row.put("name", fn.getName());
                row.put("size", fn.getBody().getNumAddresses());
                row.put("external", fn.isExternal());
                row.put("signature", fn.getPrototypeString(false, true));
                page.add(row);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("total", all.size());
            out.put("functions", page);
            if (end < all.size()) out.put("next_cursor", ApiError.encodeCursor(gson, new OffsetCursor(end)));
            return out;
        });
    }

    Map<String, Object> listSymbols(Map<String, Object> args) throws Exception {
        String kind = ApiError.reqStr(args, "kind");
        if (!List.of("imports", "exports", "globals", "strings", "classes", "namespaces").contains(kind)) {
            throw new ApiError("INVALID_ARGUMENT",
                    "kind must be imports, exports, globals, strings, classes, or namespaces", null);
        }
        String filter = ApiError.optStr(args, "filter");
        String folded = filter == null ? null : filter.toLowerCase(Locale.ROOT);
        int limit = ApiError.optInt(args, "limit", 50, 1, MAX_LIST_LIMIT);
        OffsetCursor cursor = ApiError.decodeCursor(gson, args == null ? null : args.get("cursor"), OffsetCursor.class);
        int start = cursor == null ? 0 : Math.max(0, cursor.offset());

        return ws.withReadLock(() -> {
            List<Map<String, Object>> items = collectSymbols(kind, folded);
            int end = Math.min(start + limit, items.size());
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("kind", kind);
            out.put("total", items.size());
            out.put("items", items.subList(start, end));
            if (end < items.size()) out.put("next_cursor", ApiError.encodeCursor(gson, new OffsetCursor(end)));
            return out;
        });
    }

    private List<Map<String, Object>> collectSymbols(String kind, String folded) {
        Program p = ws.program();
        List<Map<String, Object>> items = new ArrayList<>();
        switch (kind) {
            case "imports" -> addSymbolRows(p.getSymbolTable().getExternalSymbols(), folded, false, items);
            case "exports" -> {
                SymbolIterator it = p.getSymbolTable().getAllSymbols(true);
                while (it.hasNext()) {
                    Symbol s = it.next();
                    if (!s.isExternalEntryPoint()) continue;
                    if (matches(s.getName(), s.getAddress().toString(), folded)) items.add(symbolRow(s));
                }
            }
            case "globals" -> {
                SymbolIterator it = p.getSymbolTable().getSymbolIterator(true);
                while (it.hasNext()) {
                    Symbol s = it.next();
                    if (!s.isGlobal() || !s.isPrimary() || s.isExternal() || s.getSymbolType() == SymbolType.FUNCTION) {
                        continue;
                    }
                    if (!matches(s.getName(), s.getAddress().toString(), folded)) continue;
                    Map<String, Object> row = symbolRow(s);
                    Data d = p.getListing().getDefinedDataAt(s.getAddress());
                    if (d != null) {
                        row.put("data_type", d.getDataType().getDisplayName());
                        row.put("size", d.getLength());
                    }
                    items.add(row);
                }
            }
            case "strings" -> {
                DefinedStringIterator it = DefinedStringIterator.forProgram(p);
                while (it.hasNext()) {
                    Data d = it.next();
                    String val = d.getDefaultValueRepresentation();
                    String addr = d.getAddress().toString();
                    if (!matches(val, addr, folded)) continue;
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("address", addr);
                    row.put("value", val);
                    row.put("length", d.getLength());
                    row.put("data_type", d.getDataType().getDisplayName());
                    items.add(row);
                }
            }
            case "classes" -> {
                var it = p.getSymbolTable().getClassNamespaces();
                while (it.hasNext()) {
                    var cls = it.next();
                    String name = cls.getName(true);
                    if (folded != null && !name.toLowerCase(Locale.ROOT).contains(folded)) continue;
                    items.add(Map.of("name", cls.getName(), "full_name", name, "id", cls.getID()));
                }
            }
            case "namespaces" -> {
                SymbolIterator it = p.getSymbolTable().getSymbolIterator(true);
                while (it.hasNext()) {
                    Symbol s = it.next();
                    if (s.getSymbolType() != SymbolType.NAMESPACE) continue;
                    String full = s.getName(true);
                    if (folded != null && !full.toLowerCase(Locale.ROOT).contains(folded)) continue;
                    items.add(Map.of("name", s.getName(), "full_name", full, "id", s.getID()));
                }
            }
            default -> throw new ApiError("INVALID_ARGUMENT", "Unsupported kind: " + kind, null);
        }
        return items;
    }

    private static void addSymbolRows(SymbolIterator it, String folded, boolean requireGlobal, List<Map<String, Object>> out) {
        while (it.hasNext()) {
            Symbol s = it.next();
            if (requireGlobal && !s.isGlobal()) continue;
            if (matches(s.getName(true), s.getAddress().toString(), folded)) out.add(symbolRow(s));
        }
    }

    private static Map<String, Object> symbolRow(Symbol s) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", s.getName());
        row.put("full_name", s.getName(true));
        row.put("address", s.getAddress().toString());
        row.put("type", s.getSymbolType().toString());
        row.put("source", s.getSource().toString());
        return row;
    }

    private static boolean matches(String text, String addr, String folded) {
        if (folded == null) return true;
        return (text != null && text.toLowerCase(Locale.ROOT).contains(folded))
                || (addr != null && addr.toLowerCase(Locale.ROOT).contains(folded));
    }

    Map<String, Object> decompile(Map<String, Object> args) throws Exception {
        String target = ApiError.reqStr(args, "target");
        boolean includeVars = ApiError.optBool(args, "include_vars", true);
        int offset = ApiError.optInt(args, "offset", 0, 0, Integer.MAX_VALUE);

        return ws.withReadLock(() -> {
            Function fn = ws.resolveFunction(target);
            ProgramWorkspace.CachedDecompile res = ws.decompileCached(fn, DECOMPILE_TIMEOUT_SEC);
            String fullCode = res.code() == null ? "" : res.code();
            int start = Math.min(offset, fullCode.length());
            int end = Math.min(start + PSEUDOCODE_SLICE_CHARS, fullCode.length());
            boolean truncated = end < fullCode.length();

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("function", Map.of(
                    "address", fn.getEntryPoint().toString(),
                    "name", fn.getName(),
                    "signature", fn.getPrototypeString(false, true),
                    "comment", fn.getComment() == null ? "" : fn.getComment()));
            out.put("decompile_status", res.status());
            if (res.error() != null) out.put("decompile_error", res.error());
            out.put("pseudocode", fullCode.substring(start, end));
            out.put("truncated", truncated);
            if (truncated) out.put("next_offset", end);
            if (includeVars) {
                out.put("variables", res.variables());
                out.put("globals", res.globals());
            }
            return out;
        });
    }

    Map<String, Object> disassemble(Map<String, Object> args) throws Exception {
        String target = ApiError.reqStr(args, "target");
        int maxInstr = ApiError.optInt(args, "max_instructions", 100, 1, 400);
        OffsetCursor cursor = ApiError.decodeCursor(gson, args == null ? null : args.get("cursor"), OffsetCursor.class);
        int start = cursor == null ? 0 : Math.max(0, cursor.offset());

        return ws.withReadLock(() -> {
            Program p = ws.program();
            Address rawAddr = ws.parseAddress(target);
            Function fn = null;
            if (rawAddr != null) fn = p.getFunctionManager().getFunctionAt(rawAddr);
            if (fn == null && rawAddr == null) fn = ws.resolveFunction(target);

            InstructionIterator it;
            String scopeLabel;
            if (fn != null) {
                it = p.getListing().getInstructions(fn.getBody(), true);
                scopeLabel = fn.getName() + " @ " + fn.getEntryPoint();
            } else {
                Address startAddr = rawAddr != null ? rawAddr : ws.resolveFunction(target).getEntryPoint();
                it = p.getListing().getInstructions(startAddr, true);
                scopeLabel = startAddr.toString();
            }

            int skipped = 0;
            while (skipped < start && it.hasNext()) {
                it.next();
                skipped++;
            }

            List<Map<String, Object>> rows = new ArrayList<>();
            int taken = 0;
            while (taken < maxInstr && it.hasNext()) {
                Instruction ins = it.next();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", ins.getAddress().toString());
                try {
                    row.put("bytes", HexFormat.of().formatHex(ins.getBytes()));
                } catch (MemoryAccessException e) {
                    row.put("bytes", "");
                }
                String mnemonic = ins.getMnemonicString();
                String full = ins.toString();
                String operands = full.length() > mnemonic.length() ? full.substring(mnemonic.length()).trim() : "";
                row.put("mnemonic", mnemonic);
                row.put("operands", operands);
                String pre = ins.getComment(CommentType.PRE);
                String eol = ins.getComment(CommentType.EOL);
                if (pre != null && !pre.isEmpty()) row.put("pre_comment", pre);
                if (eol != null && !eol.isEmpty()) row.put("eol_comment", eol);
                rows.add(row);
                taken++;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("scope", scopeLabel);
            out.put("instructions", rows);
            if (it.hasNext()) out.put("next_cursor", ApiError.encodeCursor(gson, new OffsetCursor(start + taken)));
            return out;
        });
    }

    Map<String, Object> getXrefs(Map<String, Object> args) throws Exception {
        String target = ApiError.reqStr(args, "target");
        String kind = ApiError.optStr(args, "kind");
        if (kind == null) kind = "all";
        if (!List.of("callers", "callees", "to", "from", "all").contains(kind)) {
            throw new ApiError("INVALID_ARGUMENT", "kind must be callers, callees, to, from, or all", null);
        }
        int limit = ApiError.optInt(args, "limit", 50, 1, MAX_LIST_LIMIT);
        OffsetCursor cursor = ApiError.decodeCursor(gson, args == null ? null : args.get("cursor"), OffsetCursor.class);
        int start = cursor == null ? 0 : Math.max(0, cursor.offset());
        final String finalKind = kind;

        return ws.withReadLock(() -> {
            Program p = ws.program();
            Address addr = ws.parseAddress(target);
            Function fn = addr != null ? p.getFunctionManager().getFunctionAt(addr) : ws.resolveFunction(target);
            if (addr == null && fn != null) addr = fn.getEntryPoint();
            if (addr == null) throw new ApiError("NOT_FOUND", "Target address or function not found: " + target, null);

            List<Map<String, Object>> xrefs = new ArrayList<>();
            if (fn != null && ("callers".equals(finalKind) || "all".equals(finalKind))) {
                for (Function caller : fn.getCallingFunctions(TaskMonitor.DUMMY)) {
                    xrefs.add(Map.of("kind", "caller", "address", caller.getEntryPoint().toString(), "name", caller.getName()));
                }
            }
            if (fn != null && ("callees".equals(finalKind) || "all".equals(finalKind))) {
                for (Function callee : fn.getCalledFunctions(TaskMonitor.DUMMY)) {
                    xrefs.add(Map.of("kind", "callee", "address", callee.getEntryPoint().toString(), "name", callee.getName()));
                }
            }
            if ("to".equals(finalKind) || "all".equals(finalKind)) {
                var refs = p.getReferenceManager().getReferencesTo(addr);
                while (refs.hasNext()) {
                    Reference r = refs.next();
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("kind", "to");
                    row.put("from_address", r.getFromAddress().toString());
                    row.put("to_address", r.getToAddress().toString());
                    row.put("ref_type", r.getReferenceType().getName());
                    Function fromFn = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    if (fromFn != null) row.put("from_function", fromFn.getName());
                    xrefs.add(row);
                }
            }
            if ("from".equals(finalKind) || "all".equals(finalKind)) {
                if (fn != null) {
                    InstructionIterator it = p.getListing().getInstructions(fn.getBody(), true);
                    while (it.hasNext()) {
                        for (Reference r : p.getReferenceManager().getReferencesFrom(it.next().getAddress())) {
                            xrefs.add(fromRefRow(p, r));
                        }
                    }
                } else {
                    for (Reference r : p.getReferenceManager().getReferencesFrom(addr)) {
                        xrefs.add(fromRefRow(p, r));
                    }
                }
            }

            int end = Math.min(start + limit, xrefs.size());
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("target", addr.toString());
            out.put("total", xrefs.size());
            out.put("xrefs", xrefs.subList(start, end));
            if (end < xrefs.size()) out.put("next_cursor", ApiError.encodeCursor(gson, new OffsetCursor(end)));
            return out;
        });
    }

    private static Map<String, Object> fromRefRow(Program p, Reference r) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("kind", "from");
        row.put("from_address", r.getFromAddress().toString());
        row.put("to_address", r.getToAddress().toString());
        row.put("ref_type", r.getReferenceType().getName());
        Symbol sym = p.getSymbolTable().getPrimarySymbol(r.getToAddress());
        if (sym != null) row.put("to_symbol", sym.getName());
        return row;
    }

    Map<String, Object> readMemory(Map<String, Object> args) throws Exception {
        String addrStr = ApiError.reqStr(args, "address");
        int size = ApiError.optInt(args, "size", 64, 1, MAX_MEMORY_BYTES);
        String format = ApiError.optStr(args, "format");
        if (format == null) format = "hex";
        if (!List.of("hex", "utf8", "u32", "u64").contains(format)) {
            throw new ApiError("INVALID_ARGUMENT", "format must be hex, utf8, u32, or u64", null);
        }
        final String fmt = format;

        return ws.withReadLock(() -> {
            Address addr = ws.parseAddress(addrStr);
            if (addr == null) throw new ApiError("INVALID_ARGUMENT", "Invalid address: " + addrStr, null);
            byte[] buf = new byte[size];
            try {
                int read = ws.program().getMemory().getBytes(addr, buf);
                if (read < buf.length) buf = java.util.Arrays.copyOf(buf, read);
            } catch (MemoryAccessException e) {
                throw new ApiError("MEMORY_READ_FAILED", "Cannot read memory at " + addrStr + ": " + e.getMessage(), null);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("address", addr.toString());
            out.put("size", buf.length);
            out.put("format", fmt);
            out.put("hex", HexFormat.ofDelimiter(" ").formatHex(buf));
            if ("utf8".equals(fmt)) {
                out.put("utf8", new String(buf, StandardCharsets.UTF_8));
            } else if ("u32".equals(fmt) || "u64".equals(fmt)) {
                ByteOrder order = ws.program().getMemory().isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
                ByteBuffer bb = ByteBuffer.wrap(buf).order(order);
                int stride = "u32".equals(fmt) ? 4 : 8;
                List<String> values = new ArrayList<>();
                while (bb.remaining() >= stride) {
                    long v = stride == 4 ? Integer.toUnsignedLong(bb.getInt()) : bb.getLong();
                    values.add("0x" + Long.toHexString(v));
                }
                out.put("values", values);
            }
            return out;
        });
    }

    Map<String, Object> searchCode(Map<String, Object> args) throws Exception {
        String query = ApiError.reqStr(args, "query");
        String scope = ApiError.reqStr(args, "scope");
        if (!List.of("pseudocode", "disassembly", "bytes").contains(scope)) {
            throw new ApiError("INVALID_ARGUMENT", "scope must be pseudocode, disassembly, or bytes", null);
        }
        int limit = ApiError.optInt(args, "limit", 20, 1, 50);
        SearchCursor cursor = ApiError.decodeCursor(gson, args == null ? null : args.get("cursor"), SearchCursor.class);
        if (cursor != null && (!query.equals(cursor.query()) || !scope.equals(cursor.scope()))) {
            throw new ApiError("INVALID_CURSOR", "Cursor does not match query/scope", null);
        }

        return ws.withReadLock(() -> switch (scope) {
            case "bytes" -> searchBytes(query, limit, cursor);
            case "disassembly" -> searchDisassembly(query, limit, cursor);
            case "pseudocode" -> searchPseudocode(query, limit, cursor);
            default -> throw new ApiError("INVALID_ARGUMENT", "Invalid scope", null);
        });
    }

    private Map<String, Object> searchBytes(String query, int limit, SearchCursor cursor) {
        String compact = query.replaceAll("\\s+", "");
        if (compact.isEmpty() || compact.length() % 2 != 0 || compact.length() > 128) {
            throw new ApiError("INVALID_ARGUMENT", "bytes query must be 1..64 hex byte pairs (?? allowed)", null);
        }
        int len = compact.length() / 2;
        byte[] pattern = new byte[len];
        byte[] mask = new byte[len];
        for (int i = 0; i < len; i++) {
            String pair = compact.substring(i * 2, i * 2 + 2);
            if ("??".equals(pair)) {
                pattern[i] = 0;
                mask[i] = 0;
            } else {
                try {
                    pattern[i] = (byte) Integer.parseInt(pair, 16);
                    mask[i] = (byte) 0xff;
                } catch (NumberFormatException e) {
                    throw new ApiError("INVALID_ARGUMENT", "Invalid hex byte: " + pair, null);
                }
            }
        }
        Program p = ws.program();
        Address min = p.getMemory().getMinAddress();
        Address max = p.getMemory().getMaxAddress();
        Address start = cursor != null && cursor.nextAddress() != null ? ws.parseAddress(cursor.nextAddress()) : min;
        List<Map<String, Object>> matches = new ArrayList<>();
        Address nextCursorAddr = null;

        Address current = start;
        while (current != null && max != null && current.compareTo(max) <= 0 && matches.size() < limit) {
            Address hit = p.getMemory().findBytes(current, max, pattern, mask, true, TaskMonitor.DUMMY);
            if (hit == null) break;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", hit.toString());
            Function fn = p.getFunctionManager().getFunctionContaining(hit);
            if (fn != null) row.put("function", fn.getName());
            matches.add(row);
            try {
                current = hit.addNoWrap(1);
                nextCursorAddr = current;
            } catch (Exception e) {
                nextCursorAddr = null;
                break;
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("version", store.currentVersion());
        out.put("scope", "bytes");
        out.put("matches", matches);
        if (matches.size() == limit && nextCursorAddr != null) {
            out.put("next_cursor", ApiError.encodeCursor(gson, new SearchCursor(query, "bytes", nextCursorAddr.toString(), 0)));
        }
        return out;
    }

    private Map<String, Object> searchDisassembly(String query, int limit, SearchCursor cursor) {
        Program p = ws.program();
        String folded = query.toLowerCase(Locale.ROOT);
        Address start = cursor != null && cursor.nextAddress() != null
                ? ws.parseAddress(cursor.nextAddress())
                : p.getMemory().getMinAddress();
        InstructionIterator it = start != null ? p.getListing().getInstructions(start, true) : p.getListing().getInstructions(true);
        List<Map<String, Object>> matches = new ArrayList<>();
        int scanned = 0;
        Address lastSeen = null;
        while (it.hasNext() && matches.size() < limit && scanned < 5000) {
            Instruction ins = it.next();
            scanned++;
            lastSeen = ins.getAddress();
            String text = ins.getAddress() + " " + ins;
            if (text.toLowerCase(Locale.ROOT).contains(folded)) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("address", ins.getAddress().toString());
                row.put("instruction", ins.toString());
                Function fn = p.getFunctionManager().getFunctionContaining(ins.getAddress());
                if (fn != null) row.put("function", fn.getName());
                matches.add(row);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("version", store.currentVersion());
        out.put("scope", "disassembly");
        out.put("scanned", scanned);
        out.put("matches", matches);
        if (it.hasNext() && lastSeen != null) {
            try {
                Address next = lastSeen.addNoWrap(1);
                out.put("next_cursor", ApiError.encodeCursor(gson, new SearchCursor(query, "disassembly", next.toString(), 0)));
            } catch (Exception ignored) {}
        }
        return out;
    }

    private Map<String, Object> searchPseudocode(String query, int limit, SearchCursor cursor) throws InterruptedException {
        String folded = query.toLowerCase(Locale.ROOT);
        int fnOffset = cursor == null ? 0 : Math.max(0, cursor.offset());
        FunctionIterator it = ws.program().getFunctionManager().getFunctions(true);
        int pos = 0;
        while (pos < fnOffset && it.hasNext()) {
            it.next();
            pos++;
        }
        List<Map<String, Object>> matches = new ArrayList<>();
        int scanned = 0;
        while (it.hasNext() && scanned < 25 && matches.size() < limit) {
            Function fn = it.next();
            pos++;
            scanned++;
            if (fn.isExternal()) continue;
            ProgramWorkspace.CachedDecompile res = ws.decompileCached(fn, SEARCH_DECOMPILE_TIMEOUT_SEC);
            if (!"complete".equals(res.status()) || res.code() == null) continue;
            int idx = res.code().toLowerCase(Locale.ROOT).indexOf(folded);
            if (idx >= 0) {
                int s = Math.max(0, idx - 60);
                int e = Math.min(res.code().length(), idx + query.length() + 100);
                matches.add(Map.of(
                        "address", fn.getEntryPoint().toString(),
                        "name", fn.getName(),
                        "excerpt", res.code().substring(s, e).strip()));
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("version", store.currentVersion());
        out.put("scope", "pseudocode");
        out.put("scanned_functions", scanned);
        out.put("matches", matches);
        if (it.hasNext()) {
            out.put("next_cursor", ApiError.encodeCursor(gson, new SearchCursor(query, "pseudocode", null, pos)));
        }
        return out;
    }

    Map<String, Object> getType(Map<String, Object> args) throws Exception {
        String query = ApiError.reqStr(args, "query");
        boolean exact = ApiError.optBool(args, "exact", false);
        int limit = ApiError.optInt(args, "limit", 20, 1, 50);
        OffsetCursor cursor = ApiError.decodeCursor(gson, args == null ? null : args.get("cursor"), OffsetCursor.class);
        int start = cursor == null ? 0 : Math.max(0, cursor.offset());
        String folded = query.toLowerCase(Locale.ROOT);

        return ws.withReadLock(() -> {
            Map<String, DataType> byPath = new LinkedHashMap<>();
            for (var dtm : List.of(ws.program().getDataTypeManager(), BuiltInDataTypeManager.getDataTypeManager())) {
                Iterator<DataType> it = dtm.getAllDataTypes();
                while (it.hasNext()) {
                    DataType dt = it.next();
                    if (exact) {
                        if (dt.getName().equalsIgnoreCase(query) || dt.getPathName().equalsIgnoreCase(query)) {
                            byPath.putIfAbsent(dt.getPathName(), dt);
                        }
                    } else if (dt.getName().toLowerCase(Locale.ROOT).contains(folded)
                            || dt.getPathName().toLowerCase(Locale.ROOT).contains(folded)) {
                        byPath.putIfAbsent(dt.getPathName(), dt);
                    }
                }
            }
            List<DataType> found = new ArrayList<>(byPath.values());
            found.sort(Comparator.comparing(DataType::getPathName, String.CASE_INSENSITIVE_ORDER));
            int end = Math.min(start + limit, found.size());
            List<Map<String, Object>> page = new ArrayList<>(Math.max(0, end - start));
            for (int i = start; i < end; i++) page.add(describeType(found.get(i)));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", true);
            out.put("version", store.currentVersion());
            out.put("total", found.size());
            out.put("types", page);
            if (end < found.size()) out.put("next_cursor", ApiError.encodeCursor(gson, new OffsetCursor(end)));
            return out;
        });
    }

    private static Map<String, Object> describeType(DataType type) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", type.getName());
        row.put("path", type.getPathName());
        row.put("kind", typeKind(type));
        row.put("size", type.getLength());
        row.put("description", type.getDescription() == null ? "" : type.getDescription());
        if (type instanceof Composite composite) {
            DataTypeComponent[] comps = composite.getComponents();
            int cap = Math.min(comps.length, TYPE_COMPONENTS_CAP);
            List<Map<String, Object>> fields = new ArrayList<>(cap);
            for (int i = 0; i < cap; i++) {
                DataTypeComponent c = comps[i];
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("ordinal", c.getOrdinal());
                f.put("offset", c.getOffset());
                f.put("name", c.getFieldName() == null ? c.getDefaultFieldName() : c.getFieldName());
                f.put("type", c.getDataType().getDisplayName());
                f.put("path", c.getDataType().getPathName());
                f.put("size", c.getLength());
                if (c.getComment() != null) f.put("comment", c.getComment());
                fields.add(f);
            }
            row.put("fields", fields);
            row.put("fields_truncated", comps.length > cap);
        } else if (type instanceof ghidra.program.model.data.Enum en) {
            String[] names = en.getNames();
            long[] vals = en.getValues();
            int cap = Math.min(names.length, TYPE_COMPONENTS_CAP);
            List<Map<String, Object>> entries = new ArrayList<>(cap);
            for (int i = 0; i < cap; i++) entries.add(Map.of("name", names[i], "value", vals[i]));
            row.put("values", entries);
        } else if (type instanceof TypedefDataType td) {
            row.put("base_type", td.getDataType().getDisplayName());
            row.put("base_path", td.getDataType().getPathName());
        } else if (type instanceof Pointer ptr && ptr.getDataType() != null) {
            row.put("points_to", ptr.getDataType().getDisplayName());
            row.put("points_to_path", ptr.getDataType().getPathName());
        } else if (type instanceof Array arr) {
            row.put("element_type", arr.getDataType().getDisplayName());
            row.put("element_count", arr.getNumElements());
        }
        return row;
    }

    private static String typeKind(DataType type) {
        if (type instanceof Structure) return "structure";
        if (type instanceof Union) return "union";
        if (type instanceof Composite) return "composite";
        if (type instanceof ghidra.program.model.data.Enum) return "enum";
        if (type instanceof TypedefDataType) return "typedef";
        if (type instanceof Pointer) return "pointer";
        if (type instanceof Array) return "array";
        return "scalar";
    }
}
