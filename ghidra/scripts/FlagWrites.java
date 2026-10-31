// Elenca i riferimenti (lettura/scrittura) a un indirizzo e il contesto delle scritture.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FlagWrites extends GhidraScript {
    @Override
    protected void run() throws Exception {
        for (String t : System.getenv("S11_TARGETS").split(",")) {
            Address target = toAddr(Long.decode(t));
            println("== " + target);
            for (Reference r : getReferencesTo(target)) {
                Function f = getFunctionContaining(r.getFromAddress());
                String fn = f == null ? "?" : f.getName();
                println("   " + r.getReferenceType() + " da " + r.getFromAddress() + " in " + fn);
                if (r.getReferenceType().isWrite()) {
                    Instruction ins = getInstructionAt(r.getFromAddress());
                    for (int i = 0; i < 12 && ins != null; i++) ins = ins.getPrevious();
                    for (int i = 0; i < 16 && ins != null; i++) { println("        " + ins.getAddress() + "  " + ins); ins = ins.getNext(); }
                }
            }
        }
    }
}
