// Postscript: finds the key strings, their references (including via the L32R literal pool) and
// decompiles the functions that use them. The literal-pool step matters: on Xtensa a plain
// reference search misses most uses, because the address is loaded from a pool word.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FindProtectRefs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] needles = {"ASATIFMR", "BSMF121W", "BSMF121.", "Read Parity from InitInfo", "Bunch_RS_Recover", "load DBT Fail", "gulRSRecoverFailCnt", "PhIsOn"};
        Memory mem = currentProgram.getMemory();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<Function> seen = new HashSet<>();
        for (String n : needles) {
            Address found = mem.findBytes(mem.getMinAddress(), n.getBytes(), null, true, monitor);
            println("== " + n + " -> " + found);
            if (found == null) continue;
            // direct references
            List<Address> refsFrom = new ArrayList<>();
            for (Reference r : getReferencesTo(found)) refsFrom.add(r.getFromAddress());
            // literal pool: look for the 32-bit word holding the address, then references to that word
            byte[] le = new byte[4];
            long v = found.getOffset();
            for (int i = 0; i < 4; i++) le[i] = (byte) (v >> (8 * i));
            Address p = mem.getMinAddress();
            while ((p = mem.findBytes(p, le, null, true, monitor)) != null) {
                println("   literal at " + p);
                for (Reference r : getReferencesTo(p)) refsFrom.add(r.getFromAddress());
                p = p.add(1);
            }
            for (Address from : refsFrom) {
                Function f = getFunctionContaining(from);
                println("   used by " + from + " in " + (f == null ? "?" : f.getName() + "@" + f.getEntryPoint()));
                if (f != null && seen.add(f)) {
                    DecompileResults res = dec.decompileFunction(f, 60, monitor);
                    if (res.decompileCompleted()) println(res.getDecompiledFunction().getC());
                }
            }
        }
    }
}
