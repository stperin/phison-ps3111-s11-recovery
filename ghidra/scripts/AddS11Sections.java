// Prescript: aggiunge le sezioni 1 e 2 del firmware S11 (la 0 è il file importato a 0x5C0E0000).
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
        println("aggiunto " + name + " a " + a + " (" + data.length + " byte)");
    }
}
