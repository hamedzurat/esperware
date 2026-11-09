import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Runs the MCP tool handlers against a real analyzed program without a host approval layer. */
public class RuntimeMcpToolsProbe extends GhidraScript {
    private Object sessions;
    private Class<?> serviceClass;
    private Map<String,Object> identity;

    @Override
    public void run() throws Exception {
        URLClassLoader loader = extensionLoader(Path.of(getScriptArgs()[0]));
        serviceClass = Class.forName("org.esperware.ghidramcp.GhidraSessionService", true, loader);
        Program program = getState().getCurrentProgram();
        ProgramManager manager = (ProgramManager) Proxy.newProxyInstance(
                ProgramManager.class.getClassLoader(), new Class<?>[] {ProgramManager.class},
                (proxy, method, args) -> method.getName().equals("openProgram")
                        || method.getName().equals("getCurrentProgram") ? program
                        : method.getReturnType() == boolean.class ? false
                        : method.getReturnType() == int.class ? 0
                        : method.getReturnType() == long.class ? 0L : null);
        var constructor = serviceClass.getDeclaredConstructor(ProgramManager.class, Project.class);
        constructor.setAccessible(true);
        sessions = constructor.newInstance(manager, getState().getProject());

        Map<String,Object> opened = call("programSession", Map.of("contract_version", 1,
                "action", "open", "program", "/readability-fixture.elf"));
        identity = new LinkedHashMap<>();
        identity.put("contract_version", 1);
        identity.put("session_id", opened.get("session_id"));
        identity.put("generation", opened.get("generation"));
        identity.put("expected_revision", opened.get("revision"));

        Map<String,Object> search = call("searchPseudocode", withIdentity(Map.of(
                "query", "probe_state", "match_in", "pseudocode")));
        Map<String,Object> hit = list(search, "matches").stream()
                .filter(match -> match.get("excerpt").toString().contains("probe_state"))
                .findFirst().orElseThrow(() -> new IllegalStateException("pseudocode search missed probe_state"));
        String functionAddress = hit.get("entry_address").toString();

        Map<String,Object> typeSearch = call("searchTypes", withIdentity(Map.of("query", "ProbeState")));
        Map<String,Object> struct = list(typeSearch, "types").stream()
                .filter(type -> type.get("data_type_path").equals("/Probe/ProbeState"))
                .findFirst().orElseThrow(() -> new IllegalStateException("struct search missed ProbeState"));
        List<Map<String,Object>> fields = list(struct, "fields");
        if (fields.size() != 2 || !fields.get(0).get("offset_bytes").equals(0)
                || !fields.get(1).get("offset_bytes").equals(4)) {
            throw new IllegalStateException("unexpected ProbeState fields: " + fields);
        }
        String scalarType = fields.get(0).get("data_type_path").toString();

        Map<String,Object> inspection = inspect(functionAddress);
        Map<String,Object> global = global(inspection, "probe_state");
        if (!"/Probe/ProbeState".equals(global.get("data_type_path"))) {
            throw new IllegalStateException("wrong starting global type: " + global);
        }
        println("MCP_TOOL_PROBE initial_pseudocode=" + inspection.get("pseudocode"));

        Map<String,Object> rename = editGlobal(functionAddress, global, "rename", "mcp_probe_state");
        Map<String,Object> renamedInspection = inspect(functionAddress);
        String renamedCode = renamedInspection.get("pseudocode").toString();
        if (!renamedCode.contains("mcp_probe_state")) {
            throw new IllegalStateException("renamed global absent from pseudocode: " + renamedCode);
        }
        println("MCP_TOOL_PROBE renamed_pseudocode=" + renamedCode);
        revert(rename.get("edit_id").toString());

        Map<String,Object> afterRename = inspect(functionAddress);
        Map<String,Object> restoredGlobal = global(afterRename, "probe_state");
        Map<String,Object> typeEdit = editGlobal(functionAddress, restoredGlobal, "type", scalarType);
        Map<String,Object> changedType = inspect(functionAddress);
        println("MCP_TOOL_PROBE scalar_global=" + global(changedType, "probe_state"));
        revert(typeEdit.get("edit_id").toString());

        Map<String,Object> beforeComment = inspect(functionAddress);
        Map<String,Object> commentEdit = editGlobal(functionAddress, global(beforeComment, "probe_state"),
                "comment", "updated probe comment");
        Map<String,Object> commented = inspect(functionAddress);
        if (!"updated probe comment".equals(global(commented, "probe_state").get("comment"))) {
            throw new IllegalStateException("global comment edit did not apply");
        }
        revert(commentEdit.get("edit_id").toString());

        Map<String,Object> finalInspection = inspect(functionAddress);
        Map<String,Object> finalGlobal = global(finalInspection, "probe_state");
        if (!"/Probe/ProbeState".equals(finalGlobal.get("data_type_path"))
                || !"probe global comment".equals(finalGlobal.get("comment"))) {
            throw new IllegalStateException("revert did not restore original global: " + finalGlobal);
        }
        Map<String,Object> finalSearch = call("searchPseudocode", withIdentity(Map.of(
                "query", "probe_state", "match_in", "pseudocode")));
        println("MCP_TOOL_PROBE final_pseudocode=" + finalInspection.get("pseudocode"));
        println("MCP_TOOL_PROBE final_search_matches=" + list(finalSearch, "matches").size());
        println("MCP_TOOL_PROBE PASS");
        loader.close();
    }

    private URLClassLoader extensionLoader(Path extensionLib) throws Exception {
        URL[] jars;
        try (var files = Files.list(extensionLib)) {
            jars = files.filter(path -> path.toString().endsWith(".jar"))
                    .map(path -> {
                        try { return path.toUri().toURL(); }
                        catch (Exception failure) { throw new RuntimeException(failure); }
                    }).toArray(URL[]::new);
        }
        return new URLClassLoader(jars, ProgramManager.class.getClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (!name.startsWith("org.esperware.ghidramcp.")) return super.loadClass(name, resolve);
                synchronized (getClassLoadingLock(name)) {
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null) {
                        try { loaded = findClass(name); }
                        catch (ClassNotFoundException missing) { loaded = super.loadClass(name, false); }
                    }
                    if (resolve) resolveClass(loaded);
                    return loaded;
                }
            }
        };
    }

    @SuppressWarnings("unchecked")
    private Map<String,Object> call(String method, Map<String,Object> args) throws Exception {
        try {
            var operation = serviceClass.getDeclaredMethod(method, Map.class);
            operation.setAccessible(true);
            Map<String,Object> result = (Map<String,Object>) operation.invoke(sessions, args);
            if (!Boolean.TRUE.equals(result.get("ok"))) throw new IllegalStateException(method + " failed: " + result);
            if (identity != null && result.containsKey("revision")) {
                identity.put("expected_revision", result.get("revision"));
            }
            println("MCP_TOOL_PROBE call=" + method + " result=" + result);
            return result;
        } catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception exception) throw exception;
            throw failure;
        }
    }

    private Map<String,Object> inspect(String address) throws Exception {
        return call("inspect", withIdentity(Map.of("function_address", address)));
    }

    private Map<String,Object> editGlobal(String address, Map<String,Object> global,
            String kind, String value) throws Exception {
        Map<String,Object> target = Map.of("kind", "global", "function_address", address,
                "global_ref", global.get("reference"));
        return call("edit", withIdentity(Map.of("target", target,
                "change", Map.of("kind", kind, "value", value))));
    }

    private void revert(String editId) throws Exception {
        call("revert", withIdentity(Map.of("edit_id", editId)));
    }

    private Map<String,Object> withIdentity(Map<String,Object> fields) {
        Map<String,Object> args = new LinkedHashMap<>(identity);
        args.putAll(fields);
        return args;
    }

    @SuppressWarnings("unchecked")
    private Map<String,Object> global(Map<String,Object> inspection, String name) {
        return list(inspection, "globals").stream().filter(item -> item.get("name").equals(name))
                .findFirst().orElseThrow(() -> new IllegalStateException("missing global " + name));
    }

    @SuppressWarnings("unchecked")
    private List<Map<String,Object>> list(Map<String,Object> value, String key) {
        return (List<Map<String,Object>>) value.get(key);
    }
}
