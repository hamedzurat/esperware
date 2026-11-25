package org.esperware.ghidramcp;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** Owns the single headless GhidraProject, Program, decompiler pool, decompile cache, and read/write locks. */
final class ProgramWorkspace implements AutoCloseable {
    private static final int MAX_DECOMPILE_CACHE_ENTRIES = 512;
    private static final String PROJECT_OPTIONS = "Esperware";
    private static final String VERSION_OPTION = "History Version";
    private static final String BINARY_HASH_OPTION = "Binary SHA-256";
    static final long UNTRACKED_VERSION = -1;

    record CachedDecompile(
            String status,
            String code,
            String error,
            List<Map<String, Object>> variables,
            List<Map<String, Object>> globals) {}

    record LiveDecompile(String status, String code, String error, HighFunction highFunction) {}

    @FunctionalInterface
    interface CheckedWork<T> {
        T run() throws Exception;
    }

    private final GhidraProject project;
    private final Program program;
    private final String binaryName;
    private final String binarySha256;
    private final String ghidraVersion;
    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
    private final ArrayBlockingQueue<DecompInterface> decompPool;
    private final ConcurrentHashMap<String, CachedDecompile> decompileCache = new ConcurrentHashMap<>();
    private boolean savingVersion;
    private volatile boolean recoveryRequired;

    private ProgramWorkspace(
            GhidraProject project,
            Program program,
            String binaryName,
            String binarySha256,
            String ghidraVersion,
            int poolSize) {
        this.project = project;
        this.program = program;
        this.binaryName = binaryName;
        this.binarySha256 = binarySha256;
        this.ghidraVersion = ghidraVersion;
        int size = Math.max(1, poolSize);
        this.decompPool = new ArrayBlockingQueue<>(size);
        for (int i = 0; i < size; i++) {
            DecompInterface iface = new DecompInterface();
            iface.openProgram(program);
            decompPool.add(iface);
        }
    }

    static ProgramWorkspace open(Path binaryPath, Path workDir, Path cacheDir, int poolSize) throws Exception {
        Path absWork = workDir.toAbsolutePath().normalize();
        for (Path part : absWork) {
            if (part.getFileName().toString().startsWith(".")) {
                throw new IllegalArgumentException(
                        "--work-dir cannot contain '.'-prefixed path components (Ghidra forbids them): " + absWork);
            }
        }
        Files.createDirectories(absWork);
        Path projDir = absWork.resolve("ghidra-project");
        Path gpr = projDir.resolve("workspace.gpr");

        GhidraProject project;
        Program program;
        String binaryName;
        String sha256;

        if (Files.exists(gpr)) {
            project = GhidraProject.openProject(projDir.toString(), "workspace", true);
            program = openSoleProgram(project);
            try {
                sha256 = savedBinaryHash(program);
                if (binaryPath != null) requireMatchingHash(sha256File(binaryPath), sha256);
                binaryName = program.getName();
            } catch (Exception e) {
                project.close();
                throw e;
            }
        } else {
            if (Files.exists(absWork.resolve("history.sqlite"))) {
                throw new IOException("Workspace history exists without its saved Ghidra project");
            }
            if (binaryPath == null || !Files.isRegularFile(binaryPath)) {
                throw new IllegalArgumentException("Binary not found: " + binaryPath);
            }
            Path absBin = binaryPath.toAbsolutePath().normalize();
            binaryName = absBin.getFileName().toString();
            sha256 = sha256File(absBin);
            Path cachedProj = cacheDir != null ? cacheDir.toAbsolutePath().normalize().resolve(sha256) : null;

            if (cachedProj != null && Files.exists(cachedProj.resolve("workspace.gpr"))) {
                copyProjectDir(cachedProj, projDir);
                project = GhidraProject.openProject(projDir.toString(), "workspace", true);
                program = openSoleProgram(project);
                try {
                    requireMatchingHash(sha256, savedBinaryHash(program));
                } catch (IOException e) {
                    project.close();
                    throw e;
                }
                binaryName = program.getName();
            } else {
                Files.createDirectories(projDir);
                project = GhidraProject.createProject(projDir.toString(), "workspace", false);
                program = project.importProgram(absBin.toFile());
                if (program == null) {
                    project.close();
                    throw new IOException("Ghidra could not import " + absBin);
                }
                try {
                    validateExecutableHash(program, sha256);
                } catch (IOException e) {
                    project.close();
                    throw e;
                }
                GhidraProject.analyze(program);
                program.getOptions(PROJECT_OPTIONS).setString(BINARY_HASH_OPTION, sha256);
                project.saveAs(program, "/", binaryName, true);
                if (cachedProj != null) {
                    populateCache(projDir, cachedProj);
                }
            }
        }

        String appVer = Application.getApplicationVersion();
        return new ProgramWorkspace(project, program, binaryName, sha256, appVer == null ? "unknown" : appVer, poolSize);
    }

    Program program() {
        return program;
    }

    String binaryName() {
        return binaryName;
    }

    String binarySha256() {
        return binarySha256;
    }

    String ghidraVersion() {
        return ghidraVersion;
    }

    <T> T withReadLock(CheckedWork<T> work) throws Exception {
        rwLock.readLock().lock();
        try {
            requireUsable();
            return work.run();
        } finally {
            rwLock.readLock().unlock();
        }
    }

    <T> T withWriteLock(CheckedWork<T> work) throws Exception {
        rwLock.writeLock().lock();
        try {
            requireUsable();
            return work.run();
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /** Work must publish its version as its final step. */
    <T> T runEdit(CheckedWork<T> work) throws Exception {
        try {
            return work.run();
        } catch (Throwable failure) {
            if (savingVersion) {
                recoveryRequired = true;
            } else {
                try {
                    project.rollback(program);
                    invalidateCache();
                } catch (Throwable rollbackFailure) {
                    recoveryRequired = true;
                    failure.addSuppressed(rollbackFailure);
                }
            }
            if (recoveryRequired && failure instanceof Exception) {
                ApiError error = new ApiError("RECOVERY_REQUIRED", "Restart the server to recover the workspace", null);
                error.initCause(failure);
                throw error;
            }
            throw failure;
        }
    }

    long savedVersion() {
        return program.getOptions(PROJECT_OPTIONS).getLong(VERSION_OPTION, UNTRACKED_VERSION);
    }

    void checkEditTransaction() {
        TransactionInfo info = program.getCurrentTransactionInfo();
        if (info == null || info.getStatus() != TransactionInfo.Status.NOT_DONE) {
            throw new ApiError("EDIT_FAILED", "No active Ghidra transaction to save", null);
        }
    }

    void saveVersion(long version) throws IOException {
        savingVersion = true;
        program.getOptions(PROJECT_OPTIONS).setString(BINARY_HASH_OPTION, binarySha256);
        program.getOptions(PROJECT_OPTIONS).setLong(VERSION_OPTION, version);
        project.save(program);
    }

    void versionPublished() {
        savingVersion = false;
    }

    boolean recoveryRequired() {
        return recoveryRequired;
    }

    private void requireUsable() {
        if (recoveryRequired) {
            throw new ApiError("RECOVERY_REQUIRED", "Restart the server to recover the workspace", null);
        }
    }

    Address parseAddress(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String text = raw.trim();
        Address direct = program.getAddressFactory().getAddress(text);
        if (direct != null) return direct;
        String hex = (text.startsWith("0x") || text.startsWith("0X")) ? text.substring(2) : text;
        Address stripped = program.getAddressFactory().getAddress(hex);
        if (stripped != null) return stripped;
        try {
            long offset = Long.parseUnsignedLong(hex, 16);
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            return space.getAddress(offset);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    static boolean hasExplicitAddressPrefix(String target) {
        String trimmed = target == null ? "" : target.trim();
        return trimmed.startsWith("0x") || trimmed.startsWith("0X") || trimmed.contains(":");
    }

    Function resolveFunctionByNameOrNull(String target) {
        if (target == null || target.isBlank()) return null;
        String trimmed = target.trim();
        List<Function> exactMatches = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            if (fn.getName().equals(trimmed)) exactMatches.add(fn);
        }
        return exactMatches.size() == 1 ? exactMatches.getFirst() : null;
    }

    Function resolveFunction(String target) {
        if (target == null || target.isBlank()) {
            throw new ApiError("INVALID_ARGUMENT", "target must be a non-empty address or function name", null);
        }
        String trimmed = target.trim();
        Address addr = parseAddress(trimmed);
        if (addr != null) {
            Function exact = program.getFunctionManager().getFunctionAt(addr);
            if (exact != null) return exact;
            if (!hasExplicitAddressPrefix(trimmed)) {
                Function byName = resolveFunctionByNameOrNull(trimmed);
                if (byName != null) return byName;
            }
            Function containing = program.getFunctionManager().getFunctionContaining(addr);
            if (containing != null) return containing;
        }
        List<Function> exactMatches = new ArrayList<>();
        List<Function> ciMatches = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            if (fn.getName().equals(trimmed)) exactMatches.add(fn);
            else if (fn.getName().equalsIgnoreCase(trimmed)) ciMatches.add(fn);
        }
        List<Function> matches = !exactMatches.isEmpty() ? exactMatches : ciMatches;
        if (matches.size() == 1) return matches.getFirst();
        if (matches.size() > 1) {
            List<String> addrs = matches.stream().limit(5).map(f -> f.getEntryPoint().toString()).toList();
            throw new ApiError("AMBIGUOUS_TARGET",
                    "Multiple functions named '" + trimmed + "'; pass entry address instead: " + addrs, null);
        }
        throw new ApiError("FUNCTION_NOT_FOUND", "Function not found: " + trimmed, null);
    }

    CachedDecompile decompileCached(Function fn, int timeoutSeconds) throws InterruptedException {
        return decompileCached(fn, timeoutSeconds, null);
    }

    CachedDecompile decompileCached(Function fn, int timeoutSeconds, Long deadline) throws InterruptedException {
        String key = fn.getEntryPoint().toString();
        CachedDecompile cached = decompileCache.get(key);
        if (cached != null) return cached;

        LiveDecompile live;
        if (deadline == null) {
            live = decompileFresh(fn, timeoutSeconds);
        } else {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) return null;
            DecompInterface iface = decompPool.poll(remaining, TimeUnit.NANOSECONDS);
            if (iface == null) return null;
            remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                decompPool.add(iface);
                return null;
            }
            var monitor = TimeoutTaskMonitor.timeoutIn(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)), TimeUnit.MILLISECONDS);
            try {
                live = decompileUsing(iface, fn, timeoutSeconds, monitor);
                if (monitor.didTimeout() && !"complete".equals(live.status())) return null;
            } finally {
                monitor.cancel();
            }
        }
        List<Map<String, Object>> vars = extractVariables(fn, live.highFunction());
        List<Map<String, Object>> globals = extractReferencedGlobals(fn);
        CachedDecompile result = new CachedDecompile(live.status(), live.code(), live.error(), vars, globals);
        if ("complete".equals(live.status())) {
            if (decompileCache.size() >= MAX_DECOMPILE_CACHE_ENTRIES) decompileCache.clear();
            decompileCache.put(key, result);
        }
        return result;
    }

    LiveDecompile decompileFresh(Function fn, int timeoutSeconds) throws InterruptedException {
        return decompileUsing(decompPool.take(), fn, timeoutSeconds, TaskMonitor.DUMMY);
    }

    private LiveDecompile decompileUsing(DecompInterface iface, Function fn, int timeoutSeconds, TaskMonitor monitor) {
        try {
            DecompileResults res = iface.decompileFunction(fn, timeoutSeconds, monitor);
            if (res == null) {
                return new LiveDecompile("failed", "", "Decompiler returned no result", null);
            }
            if (res.isTimedOut()) {
                return new LiveDecompile("timed_out", "", res.getErrorMessage(), null);
            }
            if (!res.decompileCompleted() || res.getDecompiledFunction() == null) {
                return new LiveDecompile("failed", "", res.getErrorMessage(), null);
            }
            return new LiveDecompile("complete", res.getDecompiledFunction().getC(), null, res.getHighFunction());
        } finally {
            decompPool.add(iface);
        }
    }

    List<Map<String, Object>> extractVariables(Function fn, HighFunction hf) {
        List<Map<String, Object>> vars = new ArrayList<>();
        Set<Long> seenSymbolIds = new HashSet<>();
        Set<String> seenNames = new HashSet<>();

        if (hf != null && hf.getLocalSymbolMap() != null) {
            Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol hs = it.next();
                if (hs.isGlobal()) continue;
                var sym = hs.getSymbol();
                if (sym != null) seenSymbolIds.add(sym.getID());
                seenNames.add(hs.getName());
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", hs.getName());
                row.put("data_type", hs.getDataType().getDisplayName());
                row.put("data_type_path", hs.getDataType().getPathName());
                row.put("storage", hs.getStorage() == null ? "" : hs.getStorage().toString());
                row.put("kind", hs.isParameter() ? "parameter" : "local");
                Variable dbVar = findDbVar(fn, hs);
                row.put("comment", dbVar != null && dbVar.getComment() != null ? dbVar.getComment() : "");
                row.put("source", dbVar != null ? "db" : "high");
                vars.add(row);
            }
        }

        for (Variable dbVar : fn.getAllVariables()) {
            var sym = dbVar.getSymbol();
            if ((sym != null && seenSymbolIds.contains(sym.getID())) || seenNames.contains(dbVar.getName())) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", dbVar.getName());
            row.put("data_type", dbVar.getDataType().getDisplayName());
            row.put("data_type_path", dbVar.getDataType().getPathName());
            row.put("storage", dbVar.getVariableStorage().toString());
            row.put("kind", dbVar instanceof Parameter ? "parameter" : "local");
            row.put("comment", dbVar.getComment() == null ? "" : dbVar.getComment());
            row.put("source", "db");
            vars.add(row);
        }
        return vars;
    }

    private static Variable findDbVar(Function fn, HighSymbol hs) {
        var sym = hs.getSymbol();
        if (sym == null) return null;
        long targetId = sym.getID();
        for (Variable v : fn.getAllVariables()) {
            if (v.getSymbol() != null && v.getSymbol().getID() == targetId) return v;
        }
        return null;
    }

    List<Map<String, Object>> extractReferencedGlobals(Function fn) {
        Map<Long, Symbol> symbolsById = new TreeMap<>();
        Map<Long, Data> dataById = new TreeMap<>();
        InstructionIterator instructions = program.getListing().getInstructions(fn.getBody(), true);
        while (instructions.hasNext()) {
            var instr = instructions.next();
            for (Reference ref : program.getReferenceManager().getReferencesFrom(instr.getAddress())) {
                if (!ref.getReferenceType().isData()) continue;
                Data data = program.getListing().getDefinedDataContaining(ref.getToAddress());
                if (data == null) continue;
                Symbol sym = program.getSymbolTable().getPrimarySymbol(data.getAddress());
                if (sym == null || !sym.isGlobal() || sym.getSymbolType() == SymbolType.FUNCTION) continue;
                symbolsById.putIfAbsent(sym.getID(), sym);
                dataById.putIfAbsent(sym.getID(), data);
            }
        }
        List<Map<String, Object>> out = new ArrayList<>(symbolsById.size());
        for (Map.Entry<Long, Symbol> entry : symbolsById.entrySet()) {
            Symbol sym = entry.getValue();
            Data data = dataById.get(entry.getKey());
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", sym.getName());
            row.put("address", data.getAddress().toString());
            row.put("data_type", data.getDataType().getDisplayName());
            row.put("data_type_path", data.getDataType().getPathName());
            row.put("size", data.getLength());
            String eol = data.getComment(CommentType.EOL);
            row.put("comment", eol == null ? "" : eol);
            out.add(row);
        }
        return out;
    }

    /** Must be called under writeLock so no concurrent reader holds a decompiler from the pool. */
    void invalidateCache() {
        decompileCache.clear();
        for (DecompInterface iface : decompPool) {
            iface.flushCache();
        }
    }

    @Override
    public void close() {
        rwLock.writeLock().lock();
        try {
            decompileCache.clear();
            List<DecompInterface> drained = new ArrayList<>();
            decompPool.drainTo(drained);
            for (DecompInterface iface : drained) {
                try {
                    iface.closeProgram();
                    iface.dispose();
                } catch (Exception e) {
                    Msg.warn(this, "Decompiler close error: " + e.getMessage());
                }
            }
            try {
                project.close();
            } catch (Exception e) {
                Msg.warn(this, "Project close error: " + e.getMessage());
            }
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    private static Program openSoleProgram(GhidraProject project) throws IOException {
        DomainFile[] files = project.getRootFolder().getFiles();
        if (files == null || files.length == 0) {
            project.close();
            throw new IOException("Ghidra project contains no program");
        }
        Program p = project.openProgram("/", files[0].getName(), false);
        if (p == null) {
            project.close();
            throw new IOException("Could not open program " + files[0].getName());
        }
        return p;
    }

    private static String savedBinaryHash(Program program) throws IOException {
        String recorded = program.getOptions(PROJECT_OPTIONS).getString(BINARY_HASH_OPTION, program.getExecutableSHA256());
        if (recorded == null || recorded.isBlank()) return "unknown";
        validateExecutableHash(program, recorded);
        return recorded.toLowerCase(java.util.Locale.ROOT);
    }

    private static void validateExecutableHash(Program program, String hash) throws IOException {
        String executableHash = program.getExecutableSHA256();
        if (executableHash != null && executableHash.matches("[0-9a-fA-F]{64}")) {
            requireMatchingHash(hash, executableHash);
        }
    }

    private static void requireMatchingHash(String requested, String saved) throws IOException {
        if (!requested.equalsIgnoreCase(saved)) {
            throw new IOException("Binary does not match the saved workspace. Use a different work directory.");
        }
    }

    static String sha256File(Path file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[65536];
        try (InputStream in = Files.newInputStream(file)) {
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        return HexFormat.of().formatHex(md.digest());
    }

    private static void populateCache(Path projDir, Path cachedProj) {
        try {
            if (Files.exists(cachedProj)) return;
            Path cacheParent = cachedProj.getParent();
            if (cacheParent != null) Files.createDirectories(cacheParent);
            Path tmp = cachedProj.resolveSibling(".tmp-" + UUID.randomUUID());
            copyProjectDir(projDir, tmp);
            try {
                Files.move(tmp, cachedProj, StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception ignored) {
                if (!Files.exists(cachedProj)) {
                    try {
                        Files.move(tmp, cachedProj);
                    } catch (Exception ignored2) {
                        deleteTreeBestEffort(tmp);
                    }
                } else {
                    deleteTreeBestEffort(tmp);
                }
            }
        } catch (Exception e) {
            Msg.warn(ProgramWorkspace.class, "Could not populate analysis cache: " + e.getMessage());
        }
    }

    private static void copyProjectDir(Path src, Path dst) throws IOException {
        try (var stream = Files.walk(src)) {
            List<Path> paths = stream.sorted(Comparator.naturalOrder()).toList();
            for (Path p : paths) {
                String name = p.getFileName().toString();
                if (name.endsWith(".lock") || name.endsWith(".lock~")) continue;
                Path target = dst.resolve(src.relativize(p));
                if (Files.isDirectory(p)) Files.createDirectories(target);
                else Files.copy(p, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    private static void deleteTreeBestEffort(Path dir) {
        try (var stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }
}
