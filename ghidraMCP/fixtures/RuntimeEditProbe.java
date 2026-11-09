// Exercise the same Ghidra mutation primitives used by the MCP edit service.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class RuntimeEditProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function target = null;
        Variable local = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && local == null) {
            Function candidate = functions.next();
            if (candidate.isExternal()) continue;
            for (Variable variable : candidate.getAllVariables()) {
                if (!(variable instanceof Parameter)) {
                    target = candidate;
                    local = variable;
                    break;
                }
            }
        }
        if (target == null || local == null) {
            throw new IllegalStateException("Fixture has no function with a recovered local variable");
        }

        long revisionBefore = currentProgram.getModificationNumber();
        int edit = currentProgram.startTransaction("MCP runtime edit probe");
        try {
            target.setName("mcp_probe_function", SourceType.USER_DEFINED);
            target.setComment("function comment probe");
            local.setName("mcp_probe_variable", SourceType.USER_DEFINED);
            local.setComment("variable comment probe");
            local.setDataType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
            currentProgram.endTransaction(edit, true);
        } catch (Exception failure) {
            currentProgram.endTransaction(edit, false);
            throw failure;
        }

        long editedRevision = currentProgram.getModificationNumber();
        if (editedRevision <= revisionBefore || !target.getName().equals("mcp_probe_function")
                || !local.getName().equals("mcp_probe_variable")) {
            throw new IllegalStateException("Committed edit did not change symbols/revision");
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler open failed");
            DecompileResults result = decompiler.decompileFunction(target, 30, TaskMonitor.DUMMY);
            if (result == null || !result.decompileCompleted()) {
                throw new IllegalStateException("Edited function did not decompile: "
                        + (result == null ? "no result" : result.getErrorMessage()));
            }
            println("EDIT_COMMITTED function=" + target.getName() + " variable=" + local.getName()
                    + " type=" + local.getDataType().getDisplayName()
                    + " revision=" + editedRevision
                    + " pseudocode_chars=" + result.getDecompiledFunction().getC().length());
        } finally {
            decompiler.dispose();
        }

    }
}
