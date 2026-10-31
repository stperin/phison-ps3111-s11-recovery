// Prescript: adds sections 1 and 2 of the S11 firmware (section 0 is the file imported at 0x5C0E0000).
// Without this nothing resolves: cross-references land outside any defined memory block.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import java.io.*;
import java.nio.file.*;

public class AddS11Sections extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String dir = System.getenv("S11_FW_DIR");
        Memory mem = currentProgram.getMemory();
        add(mem, dir + "/plain.sec1", 0x5C0C8000L, "iram_sec1");
        add(mem, dir + "/plain.sec2", 0x60000400L, "sram_sec2");
    }

    private void add(Memory mem, String path, long base, String name) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(path));
        Address a = toAddr(base);
        MemoryBlock b = mem.createInitializedBlock(name, a, new ByteArrayInputStream(data), data.length, monitor, false);
        b.setRead(true); b.setWrite(true); b.setExecute(true);
        println("added " + name + " at " + a + " (" + data.length + " bytes)");
    }
}
