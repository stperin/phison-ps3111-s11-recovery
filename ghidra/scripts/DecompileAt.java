// Decompiles the functions containing the addresses passed as script arguments.
// Usage: analyzeHeadless ... -postScript DecompileAt.java 0x6000c44f 0x6000ca31 ...
// Output goes to the file named by S11_OUT.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.*;
import java.util.*;

public class DecompileAt extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = System.getenv("S11_OUT");
        File outDir = new File(outPath != null ? outPath : "decompiled");
        outDir.mkdirs();
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Set<String> done = new HashSet<>();
        for (String a : args) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function fn = getFunctionContaining(addr);
            if (fn == null) {
                // no function defined there: create one at the address
                fn = createFunction(addr, null);
                if (fn == null) { println("NO FUNCTION at " + a); continue; }
            }
            if (!done.add(fn.getName())) continue;
            DecompileResults r = d.decompileFunction(fn, 120, monitor);
            if (r.getDecompiledFunction() == null) { println("DECOMPILATION FAILED " + fn.getName()); continue; }
            File f = new File(outDir, fn.getName() + ".c");
            try (PrintWriter w = new PrintWriter(f)) { w.print(r.getDecompiledFunction().getC()); }
            println("OK " + a + " -> " + fn.getName() + " (" + fn.getEntryPoint() + ") " + f.getName());
        }
        d.dispose();
    }
}
