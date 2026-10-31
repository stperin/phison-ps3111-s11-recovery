// Trova chi usa il flag puntato da un literal (es. 0x60000414) e decompila le funzioni.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class TraceFlag extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        String[] lits = System.getenv("S11_LITERALS").split(",");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<Function> seen = new HashSet<>();
        for (String lit : lits) {
            Address la = toAddr(Long.decode(lit));
            long target = mem.getInt(la) & 0xffffffffL;
            println("== literal " + la + " -> flag a 0x" + Long.toHexString(target));
            // tutti i literal con lo stesso valore (stessa variabile da più pool)
            byte[] le = new byte[4];
            for (int i = 0; i < 4; i++) le[i] = (byte) (target >> (8 * i));
            Address p = mem.getMinAddress();
            List<Address> users = new ArrayList<>();
            while ((p = mem.findBytes(p, le, null, true, monitor)) != null) {
                for (Reference r : getReferencesTo(p)) users.add(r.getFromAddress());
                p = p.add(1);
            }
            for (Address from : users) {
                Function f = getFunctionContaining(from);
                println("   usato da " + from + " in " + (f == null ? "?" : f.getName()));
                if (f != null && seen.add(f)) {
                    DecompileResults res = dec.decompileFunction(f, 60, monitor);
                    if (res.decompileCompleted()) println("----- " + f.getName() + "\n" + res.getDecompiledFunction().getC());
                }
            }
        }
    }
}
