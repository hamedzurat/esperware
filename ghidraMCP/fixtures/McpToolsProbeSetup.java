import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.util.TreeSet;

/** Defines a named struct on the fixture global so MCP type/global tools have stable probe data. */
public class McpToolsProbeSetup extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address globalAddress = referencedGlobalBase();

        StructureDataType structure = new StructureDataType(
                new CategoryPath("/Probe"), "ProbeState", 0);
        structure.add(new UnsignedIntegerDataType(), 4, "value", "Input and result value");
        structure.add(new UnsignedIntegerDataType(), 4, "salt", "Mixing salt");
        DataType stored = currentProgram.getDataTypeManager().addDataType(
                structure, DataTypeConflictHandler.REPLACE_HANDLER);

        int transaction = currentProgram.startTransaction("Prepare MCP tool fixture");
        try {
            currentProgram.getListing().clearCodeUnits(globalAddress, globalAddress.add(7), false);
            currentProgram.getListing().createData(globalAddress, stored);
            Symbol global = currentProgram.getSymbolTable().getPrimarySymbol(globalAddress);
            if (global == null) {
                currentProgram.getSymbolTable().createLabel(globalAddress, "probe_state",
                        currentProgram.getGlobalNamespace(), SourceType.USER_DEFINED);
            } else {
                global.setName("probe_state", SourceType.USER_DEFINED);
            }
            currentProgram.getListing().setComment(globalAddress,
                    ghidra.program.model.listing.CommentType.EOL, "probe global comment");
            currentProgram.endTransaction(transaction, true);
        } catch (Exception failure) {
            currentProgram.endTransaction(transaction, false);
            throw failure;
        }
        println("MCP_TOOLS_FIXTURE global=" + globalAddress
                + " type=" + stored.getPathName());
    }

    private Address referencedGlobalBase() {
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.isExternal()) continue;
            TreeSet<Address> targets = new TreeSet<>();
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                for (Reference reference : currentProgram.getReferenceManager()
                        .getReferencesFrom(instructions.next().getAddress())) {
                    var block = currentProgram.getMemory().getBlock(reference.getToAddress());
                    if (reference.getReferenceType().isData() && block != null
                            && block.isWrite() && ".bss".equals(block.getName())) {
                        targets.add(reference.getToAddress());
                    }
                }
            }
            if (targets.size() >= 2) return targets.first();
        }
        throw new IllegalStateException("Could not locate the fixture's referenced state global");
    }
}
