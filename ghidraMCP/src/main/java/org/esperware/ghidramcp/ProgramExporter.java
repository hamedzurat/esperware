package org.esperware.ghidramcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.sourcemap.SourceMapEntryIterator;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Exports a zero-duplication Ghidra pseudocode and metadata snapshot into &lt;work-dir&gt;/code/v&lt;version&gt;/. */
final class ProgramExporter {
    private static final int DECOMPILE_TIMEOUT_SEC = 30;

    private final ProgramWorkspace ws;
    private final InspectService inspect;
    private final Path workDir;
    private final Object exportLock = new Object();
    private final Gson compactGson = new GsonBuilder().disableHtmlEscaping().create();
    private final Gson prettyGson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private record LineSpan(String file, int line, String start, String end) {}

    private record FunctionExport(
            Function fn,
            ProgramWorkspace.CachedDecompile decompile,
            String primaryRawSource,
            String mappedSrcFile,
            int minLine,
            int maxLine,
            List<LineSpan> lines) {}

    ProgramExporter(ProgramWorkspace ws, InspectService inspect, Path workDir) {
        this.ws = ws;
        this.inspect = inspect;
        this.workDir = workDir.toAbsolutePath().normalize();
    }

    Map<String, Object> export(long version) throws Exception {
        return ws.withReadLock(() -> exportUnderReadLock(version));
    }

    Map<String, Object> exportCurrent(VersionStore store) throws Exception {
        return ws.withReadLock(() -> exportUnderReadLock(store.currentVersion()));
    }

    private Map<String, Object> exportUnderReadLock(long version) throws Exception {
        synchronized (exportLock) {
            Program program = ws.program();
            List<Function> functions = collectFunctions(program);
            List<ProgramWorkspace.CachedDecompile> decompiled = decompileAll(functions);

            SourceFileManager sfm = program.getSourceFileManager();
            List<String> rawPrimaryFiles = new ArrayList<>(functions.size());
            List<List<SourceMapEntry>> rawEntriesPerFn = new ArrayList<>(functions.size());
            Set<String> distinctRawSources = new LinkedHashSet<>();

            for (Function fn : functions) {
                List<SourceMapEntry> entries = collectSourceEntries(sfm, fn);
                rawEntriesPerFn.add(entries);
                String primary = pickPrimarySource(fn, entries);
                rawPrimaryFiles.add(primary);
                if (primary != null) distinctRawSources.add(primary);
            }

            Map<String, String> sourceMap = normalizeSourcePaths(distinctRawSources);
            List<FunctionExport> fnExports = new ArrayList<>(functions.size());
            Map<String, List<FunctionExport>> bySourceFile = new LinkedHashMap<>();
            int decompiledCount = 0;

            for (int i = 0; i < functions.size(); i++) {
                Function fn = functions.get(i);
                ProgramWorkspace.CachedDecompile dec = decompiled.get(i);
                if ("complete".equals(dec.status())) decompiledCount++;
                String primary = rawPrimaryFiles.get(i);
                String srcFile = primary != null ? sourceMap.get(primary) : null;
                if (srcFile == null) {
                    srcFile = classifyFallbackSource(
                            fallbackNamespaceParts(fn),
                            sectionName(program, fn),
                            fn.getEntryPoint().toString());
                }
                List<SourceMapEntry> entries = rawEntriesPerFn.get(i);
                List<LineSpan> lines = new ArrayList<>(entries.size());
                int minLine = Integer.MAX_VALUE;
                int maxLine = Integer.MIN_VALUE;
                for (SourceMapEntry e : entries) {
                    String fPath = sourceFilePath(e.getSourceFile());
                    if (fPath == null) continue;
                    int ln = e.getLineNumber();
                    String start = e.getBaseAddress().toString();
                    String end = (e.getRange() != null ? e.getRange().getMaxAddress() : e.getBaseAddress()).toString();
                    lines.add(new LineSpan(fPath, ln, start, end));
                    if (primary != null && primary.equals(fPath) && ln > 0) {
                        minLine = Math.min(minLine, ln);
                        maxLine = Math.max(maxLine, ln);
                    }
                }
                FunctionExport fx = new FunctionExport(fn, dec, primary, srcFile, minLine, maxLine, lines);
                fnExports.add(fx);
                bySourceFile.computeIfAbsent(srcFile, k -> new ArrayList<>()).add(fx);
            }

            Path codeRoot = workDir.resolve("code");
            Files.createDirectories(codeRoot);
            // Never use '.'-prefixed segments under workDir; Ghidra forbids them in project paths.
            Path stageDir = codeRoot.resolve("tmp-v" + version + "-" + UUID.randomUUID());
            Files.createDirectories(stageDir);

            try {
                writeTypesHeader(program, stageDir.resolve("types.h"));
                int srcFileCount = writeSourceFiles(stageDir, bySourceFile);
                writeFunctionsJsonl(stageDir.resolve("functions.jsonl"), fnExports);
                long edgeCount = writeCallgraphJsonl(program, stageDir.resolve("callgraph.jsonl"), functions);
                Map<String, Object> symbolsSummary = writeSymbolsJson(stageDir.resolve("symbols.json"));

                List<String> files = listRelativeFiles(stageDir);
                files.add("manifest.json");
                files.sort(String::compareTo);

                Map<String, Object> counts = new LinkedHashMap<>();
                counts.put("functions", fnExports.size());
                counts.put("decompiled", decompiledCount);
                counts.put("failed", fnExports.size() - decompiledCount);
                counts.put("types", program.getDataTypeManager().getDataTypeCount(false));
                counts.put("globals", symbolsSummary.get("globals_count"));
                counts.put("strings", symbolsSummary.get("strings_count"));
                counts.put("edges", edgeCount);
                counts.put("source_files", srcFileCount);

                Map<String, Object> manifest = new LinkedHashMap<>(inspect.collectProgramMetadata(version));
                manifest.put("counts", counts);
                manifest.put("files", files);
                Files.writeString(stageDir.resolve("manifest.json"), prettyGson.toJson(manifest) + "\n", StandardCharsets.UTF_8);

                Path targetDir = codeRoot.resolve("v" + version);
                swapDirectory(stageDir, targetDir, codeRoot, version);

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("ok", true);
                result.put("version", version);
                result.put("dir", "code/v" + version);
                result.put("path", targetDir.toAbsolutePath().toString());
                result.put("counts", counts);
                result.put("files", files);
                return result;
            } finally {
                deleteTreeBestEffort(stageDir);
            }
        }
    }

    private List<Function> collectFunctions(Program program) {
        List<Function> functions = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            if (fn.isExternal()) continue;
            MemoryBlock block = program.getMemory().getBlock(fn.getEntryPoint());
            if (block != null && block.isExternalBlock()) continue;
            functions.add(fn);
        }
        functions.sort(Comparator.comparing(Function::getEntryPoint));
        return functions;
    }

    private static List<String> fallbackNamespaceParts(Function fn) {
        Namespace ns = fn.getParentNamespace();
        if (ns == null || ns.isGlobal() || ns.isExternal() || ns.isLibrary()) {
            return List.of();
        }
        return ns.getPathList(false);
    }

    private static String sectionName(Program program, Function fn) {
        MemoryBlock block = program.getMemory().getBlock(fn.getEntryPoint());
        return block == null ? null : block.getName();
    }

    static String classifyFallbackSource(List<String> namespaceParts, String sectionName, String entryAddress) {
        if (namespaceParts != null && !namespaceParts.isEmpty()) {
            List<String> cleanParts = new ArrayList<>(namespaceParts.size());
            for (String part : namespaceParts) {
                String clean = sanitizeSegment(part);
                if (!clean.isEmpty()) cleanParts.add(clean);
            }
            if (!cleanParts.isEmpty()) {
                return "src/_ns/" + String.join("/", cleanParts) + ".c";
            }
        }
        if (".text".equals(sectionName) || "__text".equals(sectionName)) {
            String addr = sanitizeSegment(entryAddress);
            return "src/_text/" + (addr.isEmpty() ? "unknown" : addr) + ".c";
        }
        String sec = sectionName == null ? "" : sectionName.trim();
        while (sec.startsWith(".")) sec = sec.substring(1);
        sec = sanitizeSegment(sec);
        return "src/_sec/" + (sec.isEmpty() ? "unknown" : sec) + ".c";
    }

    private List<ProgramWorkspace.CachedDecompile> decompileAll(List<Function> functions)
            throws InterruptedException {
        List<ProgramWorkspace.CachedDecompile> out = new ArrayList<>(functions.size());
        if (functions.isEmpty()) return out;

        List<Future<ProgramWorkspace.CachedDecompile>> futures = new ArrayList<>(functions.size());
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (Function fn : functions) {
                futures.add(executor.submit(() -> ws.decompileCached(fn, DECOMPILE_TIMEOUT_SEC)));
            }
            try {
                for (Future<ProgramWorkspace.CachedDecompile> f : futures) {
                    out.add(f.get());
                }
            } catch (InterruptedException ie) {
                for (Future<ProgramWorkspace.CachedDecompile> f : futures) f.cancel(true);
                Thread.currentThread().interrupt();
                throw ie;
            } catch (ExecutionException ee) {
                for (Future<ProgramWorkspace.CachedDecompile> f : futures) f.cancel(true);
                Throwable cause = ee.getCause();
                if (cause instanceof RuntimeException re) throw re;
                if (cause instanceof Error err) throw err;
                throw new RuntimeException(cause);
            }
        }
        return out;
    }

    private static List<SourceMapEntry> collectSourceEntries(SourceFileManager sfm, Function fn) {
        AddressSetView body = fn.getBody();
        if (body == null || body.isEmpty()) return List.of();
        Map<String, SourceMapEntry> seen = new LinkedHashMap<>();
        for (AddressRange range : body) {
            for (SourceMapEntry e : sfm.getSourceMapEntries(range.getMinAddress())) {
                addMatchingSourceEntry(body, e, seen);
            }
            SourceMapEntryIterator it = sfm.getSourceMapEntryIterator(range.getMinAddress(), true);
            while (it.hasNext()) {
                SourceMapEntry e = it.next();
                if (e.getBaseAddress().compareTo(range.getMaxAddress()) > 0) break;
                addMatchingSourceEntry(body, e, seen);
            }
        }
        return new ArrayList<>(seen.values());
    }

    private static void addMatchingSourceEntry(
            AddressSetView body, SourceMapEntry entry, Map<String, SourceMapEntry> seen) {
        if (entry == null) return;
        AddressRange range = entry.getRange();
        boolean matches = range != null ? body.intersects(range) : body.contains(entry.getBaseAddress());
        if (!matches) return;
        String file = sourceFilePath(entry.getSourceFile());
        String key = entry.getBaseAddress() + "\0" + entry.getLineNumber() + "\0" + (file == null ? "" : file);
        seen.putIfAbsent(key, entry);
    }

    private static String pickPrimarySource(Function fn, List<SourceMapEntry> entries) {
        if (entries.isEmpty()) return null;
        Address entryPoint = fn.getEntryPoint();
        for (SourceMapEntry e : entries) {
            AddressRange range = e.getRange();
            boolean coversEntry = range != null ? range.contains(entryPoint) : e.getBaseAddress().equals(entryPoint);
            if (coversEntry) {
                String path = sourceFilePath(e.getSourceFile());
                if (path != null) return path;
            }
        }
        for (SourceMapEntry e : entries) {
            String path = sourceFilePath(e.getSourceFile());
            if (path != null) return path;
        }
        return null;
    }

    private static String sourceFilePath(SourceFile sf) {
        if (sf == null) return null;
        String path = sf.getPath();
        if (path != null && !path.isBlank()) return path;
        String name = sf.getFilename();
        if (name != null && !name.isBlank()) return name;
        String raw = sf.toString();
        return (raw == null || raw.isBlank()) ? null : raw;
    }

    private static void writeTypesHeader(Program program, Path outFile) throws Exception {
        try (Writer w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            new DataTypeWriter(program.getDataTypeManager(), w).write(TaskMonitor.DUMMY);
        }
        if (Files.readString(outFile, StandardCharsets.UTF_8).isBlank()) {
            Files.writeString(outFile, "/* No program-defined data types */\n", StandardCharsets.UTF_8);
        }
    }

    private static int writeSourceFiles(Path stageDir, Map<String, List<FunctionExport>> bySourceFile)
            throws IOException {
        Path typesHeader = stageDir.resolve("types.h");
        List<String> sortedFiles = new ArrayList<>(bySourceFile.keySet());
        sortedFiles.sort(String::compareTo);

        for (String relPath : sortedFiles) {
            Path target = stageDir.resolve(relPath);
            Files.createDirectories(target.getParent());
            String includeRel = target.getParent().relativize(typesHeader).toString().replace('\\', '/');

            List<FunctionExport> fns = new ArrayList<>(bySourceFile.get(relPath));
            fns.sort(Comparator.comparingInt(FunctionExport::minLine)
                    .thenComparing(fx -> fx.fn().getEntryPoint()));

            try (BufferedWriter bw = Files.newBufferedWriter(target, StandardCharsets.UTF_8)) {
                bw.write("#include \"");
                bw.write(includeRel);
                bw.write("\"\n\n");
                for (int i = 0; i < fns.size(); i++) {
                    FunctionExport fx = fns.get(i);
                    if (i > 0) bw.write("\n");
                    bw.write("/* @");
                    bw.write(fx.fn().getEntryPoint().toString());
                    if (fx.primaryRawSource() != null && fx.minLine() != Integer.MAX_VALUE) {
                        bw.write(" ");
                        bw.write(fx.primaryRawSource());
                        bw.write(":");
                        bw.write(Integer.toString(fx.minLine()));
                        if (fx.maxLine() > fx.minLine()) {
                            bw.write("-");
                            bw.write(Integer.toString(fx.maxLine()));
                        }
                    }
                    bw.write(" */\n");
                    if ("complete".equals(fx.decompile().status()) && fx.decompile().code() != null) {
                        bw.write(fx.decompile().code().strip());
                    } else {
                        bw.write("/* decompile ");
                        bw.write(fx.decompile().status());
                        if (fx.decompile().error() != null && !fx.decompile().error().isBlank()) {
                            bw.write(": ");
                            bw.write(fx.decompile().error().replace("*/", "* /"));
                        }
                        bw.write(" */");
                    }
                    bw.write("\n");
                }
            }
        }
        return sortedFiles.size();
    }

    private void writeFunctionsJsonl(Path outFile, List<FunctionExport> fnExports) throws IOException {
        try (BufferedWriter bw = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            for (FunctionExport fx : fnExports) {
                Function fn = fx.fn();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("entry_address", fn.getEntryPoint().toString());
                List<Map<String, String>> ranges = new ArrayList<>();
                for (AddressRange r : fn.getBody()) {
                    ranges.add(Map.of(
                            "start", r.getMinAddress().toString(),
                            "end", r.getMaxAddress().toString()));
                }
                row.put("body_ranges", ranges);
                row.put("size", fn.getBody().getNumAddresses());
                row.put("name", fn.getName());
                row.put("namespace", fn.getParentNamespace().getName(true));
                row.put("signature", fn.getPrototypeString(false, true));
                row.put("calling_convention", fn.getCallingConventionName());
                row.put("is_thunk", fn.isThunk());
                String comment = fn.getComment();
                if (comment != null && !comment.isEmpty()) row.put("comment", comment);
                row.put("src_file", fx.mappedSrcFile());
                row.put("decompile_status", fx.decompile().status());
                if (fx.decompile().error() != null) row.put("decompile_error", fx.decompile().error());
                row.put("variables", fx.decompile().variables());
                if (!fx.lines().isEmpty()) row.put("lines", fx.lines());
                bw.write(compactGson.toJson(row));
                bw.write('\n');
            }
        }
    }

    private long writeCallgraphJsonl(Program program, Path outFile, List<Function> functions) throws IOException {
        long edges = 0;
        try (BufferedWriter bw = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            for (Function fn : functions) {
                String fnName = fn.getName();
                String fnEntry = fn.getEntryPoint().toString();
                Set<String> seenEdges = new LinkedHashSet<>();
                Set<String> emittedCallees = new HashSet<>();

                InstructionIterator insIt = program.getListing().getInstructions(fn.getBody(), true);
                while (insIt.hasNext()) {
                    Instruction ins = insIt.next();
                    String fromAddr = ins.getAddress().toString();
                    for (Reference r : program.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                        if (r.getReferenceType().isCall()) {
                            Address to = r.getToAddress();
                            Function callee = program.getFunctionManager().getFunctionAt(to);
                            String toAddr = to.toString();
                            String toName;
                            if (callee != null) {
                                toName = callee.getName();
                                emittedCallees.add(callee.getEntryPoint().toString());
                            } else {
                                Symbol sym = program.getSymbolTable().getPrimarySymbol(to);
                                toName = sym != null ? sym.getName(true) : toAddr;
                            }
                            if (emitEdge(bw, seenEdges, fromAddr, fnName, fnEntry, toAddr, toName, "call")) edges++;
                        } else if (r.getReferenceType().isData()) {
                            Data d = program.getListing().getDefinedDataContaining(r.getToAddress());
                            if (d == null) continue;
                            Address dataAddr = d.getAddress();
                            Symbol sym = program.getSymbolTable().getPrimarySymbol(dataAddr);
                            if (d.hasStringValue()) {
                                String toName = sym != null ? sym.getName() : dataAddr.toString();
                                if (emitEdge(bw, seenEdges, fromAddr, fnName, fnEntry, dataAddr.toString(), toName, "string")) {
                                    edges++;
                                }
                            } else if (sym != null && sym.isGlobal() && sym.getSymbolType() != SymbolType.FUNCTION) {
                                if (emitEdge(bw, seenEdges, fromAddr, fnName, fnEntry, dataAddr.toString(), sym.getName(), "data")) {
                                    edges++;
                                }
                            }
                        }
                    }
                }

                // -O1 tail calls can lower to jumps without isCall() refType.
                List<Function> called = new ArrayList<>(fn.getCalledFunctions(TaskMonitor.DUMMY));
                called.sort(Comparator.comparing(Function::getEntryPoint));
                for (Function callee : called) {
                    String calleeAddr = callee.getEntryPoint().toString();
                    if (!emittedCallees.contains(calleeAddr)) {
                        if (emitEdge(bw, seenEdges, fnEntry, fnName, fnEntry, calleeAddr, callee.getName(), "call")) {
                            edges++;
                        }
                    }
                }
            }
        }
        return edges;
    }

    private boolean emitEdge(
            BufferedWriter bw,
            Set<String> seen,
            String fromAddr,
            String fromFn,
            String fromFnAddr,
            String toAddr,
            String toName,
            String kind) throws IOException {
        if (!seen.add(fromAddr + "\0" + toAddr + "\0" + kind)) return false;
        Map<String, Object> edge = new LinkedHashMap<>();
        edge.put("from_addr", fromAddr);
        edge.put("from_fn", fromFn);
        edge.put("from_fn_addr", fromFnAddr);
        edge.put("to_addr", toAddr);
        edge.put("to_name", toName);
        edge.put("kind", kind);
        bw.write(compactGson.toJson(edge));
        bw.write('\n');
        return true;
    }

    private Map<String, Object> writeSymbolsJson(Path outFile) throws IOException {
        List<Map<String, Object>> globals = inspect.collectSymbols("globals", null);
        List<Map<String, Object>> strings = inspect.collectSymbols("strings", null);
        List<Map<String, Object>> imports = inspect.collectSymbols("imports", null);
        List<Map<String, Object>> exports = inspect.collectSymbols("exports", null);
        List<Map<String, Object>> classes = inspect.collectSymbols("classes", null);
        List<Map<String, Object>> namespaces = inspect.collectSymbols("namespaces", null);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("globals", globals);
        payload.put("strings", strings);
        payload.put("imports", imports);
        payload.put("exports", exports);
        payload.put("classes", classes);
        payload.put("namespaces", namespaces);
        Files.writeString(outFile, prettyGson.toJson(payload) + "\n", StandardCharsets.UTF_8);

        return Map.of("globals_count", globals.size(), "strings_count", strings.size());
    }

    private static List<String> listRelativeFiles(Path root) throws IOException {
        List<String> files = new ArrayList<>();
        try (var stream = Files.walk(root)) {
            stream.filter(Files::isRegularFile).forEach(p ->
                    files.add(root.relativize(p).toString().replace('\\', '/')));
        }
        files.sort(String::compareTo);
        return files;
    }

    private static void swapDirectory(Path stageDir, Path targetDir, Path codeRoot, long version) throws IOException {
        Path backupDir = null;
        try {
            if (Files.exists(targetDir)) {
                backupDir = codeRoot.resolve("old-v" + version + "-" + UUID.randomUUID());
                moveDir(targetDir, backupDir);
            }
            moveDir(stageDir, targetDir);
            if (backupDir != null) deleteTreeBestEffort(backupDir);
        } catch (IOException | RuntimeException ex) {
            if (backupDir != null && Files.exists(backupDir) && !Files.exists(targetDir)) {
                try { moveDir(backupDir, targetDir); } catch (IOException suppressed) { ex.addSuppressed(suppressed); }
            }
            throw ex;
        }
    }

    private static void moveDir(Path src, Path dst) throws IOException {
        try {
            Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ignored) {
            Files.move(src, dst);
        }
    }

    private static void deleteTreeBestEffort(Path dir) {
        if (dir == null || !Files.exists(dir)) return;
        try (var stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }

    static Map<String, String> normalizeSourcePaths(Collection<String> rawPaths) {
        Map<String, String> result = new LinkedHashMap<>();
        if (rawPaths == null || rawPaths.isEmpty()) return result;

        Set<String> distinct = new TreeSet<>();
        for (String raw : rawPaths) {
            if (raw != null && !raw.isBlank()) distinct.add(raw);
        }
        if (distinct.isEmpty()) return result;

        List<String> external = new ArrayList<>();
        List<String> project = new ArrayList<>();
        Map<String, List<String>> resolvedProjectSegs = new HashMap<>();

        for (String raw : distinct) {
            String norm = raw.trim().replace('\\', '/').replaceAll("/+", "/");
            if (isExternalSourcePath(norm)) {
                external.add(raw);
            } else {
                project.add(raw);
                resolvedProjectSegs.put(raw, cleanSegments(norm, true));
            }
        }

        Set<String> usedTargets = new HashSet<>();

        if (project.size() == 1) {
            String raw = project.getFirst();
            List<String> segs = resolvedProjectSegs.get(raw);
            String file = segs.isEmpty() ? "_file.c" : segs.getLast();
            result.put(raw, reserveUniqueTarget("src/" + file, usedTargets));
        } else if (project.size() > 1) {
            List<List<String>> dirLists = new ArrayList<>(project.size());
            for (String raw : project) {
                List<String> segs = resolvedProjectSegs.get(raw);
                dirLists.add(segs.size() > 1 ? segs.subList(0, segs.size() - 1) : List.of());
            }
            int commonPrefix = commonPrefixLength(dirLists);
            for (String raw : project) {
                List<String> segs = resolvedProjectSegs.get(raw);
                List<String> relSegs = commonPrefix < segs.size()
                        ? segs.subList(commonPrefix, segs.size())
                        : (segs.isEmpty() ? List.of("_file.c") : List.of(segs.getLast()));
                result.put(raw, reserveUniqueTarget("src/" + String.join("/", relSegs), usedTargets));
            }
        }

        for (String raw : external) {
            String norm = raw.trim().replace('\\', '/').replaceAll("/+", "/");
            List<String> segs = cleanSegments(norm, false);
            if (segs.isEmpty()) segs = List.of("_external.c");
            result.put(raw, reserveUniqueTarget("src/_external/" + String.join("/", segs), usedTargets));
        }
        return result;
    }

    private static boolean isExternalSourcePath(String norm) {
        return norm.startsWith("/usr/")
                || norm.startsWith("/lib/")
                || norm.startsWith("/lib64/")
                || norm.startsWith("/opt/")
                || norm.startsWith("/include/")
                || norm.startsWith("<");
    }

    private static List<String> cleanSegments(String norm, boolean collapseDotDot) {
        List<String> rawParts = new ArrayList<>();
        for (String part : norm.split("/")) {
            if (part.isEmpty() || ".".equals(part)) continue;
            if ("..".equals(part)) {
                if (collapseDotDot && !rawParts.isEmpty()) rawParts.removeLast();
                continue;
            }
            rawParts.add(part);
        }
        List<String> out = new ArrayList<>(rawParts.size());
        for (String part : rawParts) {
            String clean = sanitizeSegment(part);
            if (!clean.isEmpty()) out.add(clean);
        }
        return out;
    }

    private static String sanitizeSegment(String part) {
        if (part == null) return "";
        String trimmed = part.trim();
        if (trimmed.isEmpty() || ".".equals(trimmed) || "..".equals(trimmed)) return "";
        String clean = trimmed.replaceAll("[^A-Za-z0-9._+-]", "_");
        if (clean.startsWith(".")) clean = "_" + clean.substring(1);
        return clean;
    }

    private static int commonPrefixLength(List<List<String>> dirLists) {
        int len = dirLists.getFirst().size();
        for (int i = 1; i < dirLists.size(); i++) {
            List<String> other = dirLists.get(i);
            len = Math.min(len, other.size());
            int match = 0;
            while (match < len && dirLists.getFirst().get(match).equals(other.get(match))) {
                match++;
            }
            len = match;
        }
        return len;
    }

    private static String reserveUniqueTarget(String candidate, Set<String> usedTargets) {
        if (usedTargets.add(candidate)) return candidate;
        int slash = candidate.lastIndexOf('/');
        int dot = candidate.lastIndexOf('.');
        String base = (dot > slash) ? candidate.substring(0, dot) : candidate;
        String ext = (dot > slash) ? candidate.substring(dot) : "";
        int n = 2;
        while (true) {
            String next = base + "_" + n + ext;
            if (usedTargets.add(next)) return next;
            n++;
        }
    }
}
