// Reopen an analyzed fixture project after RuntimeEditProbe and verify the save.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class RuntimeReopenProbe extends GhidraScript {
    @Override
    public void run() {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (!function.getName().equals("mcp_probe_function")) continue;
            boolean foundVariable = false;
            for (var variable : function.getAllVariables()) {
                if (variable.getName().equals("mcp_probe_variable")) {
                    foundVariable = true;
                    println("EDIT_REOPENED function=" + function.getName()
                            + " variable=" + variable.getName()
                            + " type=" + variable.getDataType().getDisplayName());
                    break;
                }
            }
            if (!foundVariable) throw new IllegalStateException("Saved variable rename was not found");
            return;
        }
        throw new IllegalStateException("Saved function rename was not found after reopen");
    }
}
