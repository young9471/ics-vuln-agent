// Ghidra headless post-script. Prints tab-separated FUNC/EXT/STRING records.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.FileWriter;
import java.io.PrintWriter;

public class GhidraExport extends GhidraScript {
    private static String clean(String s) {
        if (s == null) return "";
        return s.replace("\t", " ").replace("\r", " ").replace("\n", " ").trim();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("output path required");
        PrintWriter w = new PrintWriter(new FileWriter(args[0]));
        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            for (Function f : fm.getFunctions(true)) {
                w.println("FUNC\t" + f.getEntryPoint() + "\t" + clean(f.getName()));
            }
            SymbolTable st = currentProgram.getSymbolTable();
            for (Symbol s : st.getAllSymbols(true)) {
                if (s.isExternal()) w.println("EXT\t" + clean(s.getName()));
            }
            Listing listing = currentProgram.getListing();
            for (Data d : listing.getDefinedData(true)) {
                Object v = d.getValue();
                if (v instanceof String) {
                    String s = clean((String) v);
                    if (s.length() >= 4) w.println("STRING\t" + d.getAddress() + "\t" + s);
                }
            }
        } finally {
            w.close();
        }
    }
}
