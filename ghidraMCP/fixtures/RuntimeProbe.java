// Run with analyzeHeadless -postScript RuntimeProbe.java against the stripped fixture.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.TaskMonitor;

public class RuntimeProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function function = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function candidate = functions.next();
            if (!candidate.isExternal()) {
                function = candidate;
                break;
            }
        }
        if (function == null) throw new IllegalStateException("No analyzed function in fixture");
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler could not open fixture program");
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (result == null || !result.decompileCompleted()) {
                throw new IllegalStateException("Decompilation failed: "
                        + (result == null ? "no result" : result.getErrorMessage()));
            }
            println("GHIDRA_MCP_RUNTIME_PROBE function=" + function.getEntryPoint()
                    + " name=" + function.getName()
                    + " pseudocode_chars=" + result.getDecompiledFunction().getC().length());
        } finally {
            decompiler.dispose();
        }
    }
}
