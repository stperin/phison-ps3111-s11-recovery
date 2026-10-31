// Labels the PS3111-S11 (firmware SBFM21.1) addresses established in this repository,
// so a freshly loaded firmware image comes up with names instead of FUN_/DAT_.
//
// Run after AddS11Sections.java:
//   analyzeHeadless <proj> <name> -process -noanalysis -scriptPath ghidra/scripts \
//       -postScript LabelS11.java
//
// Addresses are firmware-version specific. Verify before trusting them on another build.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class LabelS11 extends GhidraScript {

    // address, name, comment
    private static final String[][] FUNCS = {
        {"0x60016c4c", "system_area_mount",      "Init scan: walks system blocks, classifies page 0 by OOB magic, sets protect bit 2 on ERROR_UNIT"},
        {"0x60004c4c", "identify_device",        "Reports SATAFIRM S11 / SBFM21W1 when protect_flag != 0"},
        {"0x6003bde8", "nand_context_init",      "Sets protect bit 0 when NAND context +0xfec is non-zero"},
        {"0x60056864", "protect_bit1_from_pin",  "Sets/clears protect bit 1 from reg+0x31c bit 9"},
        {"0x6000892c", "protect_mode_hw_setup",  "Runs only when protect_flag & 0x0c"},
        {"0x6000c1f0", "flash_io_engine",        "Works on the 0x58-byte NAND command descriptors"},
        {"0x60047ba8", "protect_flag_clear_init","Clears protect_flag during initialisation"},
    };

    private static final String[][] DATA = {
        {"0x5C0CB5F0", "protect_flag",             "Protect-mode bitfield. Non-zero => SATAFIRM S11"},
        {"0x5C0CEAAC", "error_unit_block",         "Block where the scan saw ERROR_UNIT (firmware numbering)"},
        {"0x5C0CE6DA", "system_unit_header_block", "0xFF = none found"},
        {"0x5C0CE6DB", "block_map_block",          "0xFF = none found"},
        {"0x5C0CE9AB", "scan_block_limit",         "Starts at 100, then taken from config"},
        {"0x5C0CE6B4", "ce_count",                 ""},
        {"0x5C0CEAE8", "ce_bitmap",                ""},
        {"0x5C0CB5F8", "nand_descriptor_array",    "0x58 bytes per slot"},
        {"0x6005CD00", "found_blocks",             "[0..5] system unit headers, [6..11] block maps"},
        {"0x6005CD10", "found_sequences",          "u32 per entry"},
        {"0x50001200", "scan_oob_buffer",          "4 slots of 0x100, filled by the init scan"},
    };

    public void run() throws Exception {
        int named = 0, commented = 0;
        for (String[] e : FUNCS) {
            Address a = toAddr(e[0]);
            Function f = getFunctionAt(a);
            if (f == null) f = createFunction(a, e[1]);
            if (f == null) { println("no function at " + e[0] + ", skipped"); continue; }
            f.setName(e[1], SourceType.USER_DEFINED);
            f.setComment(e[2]);
            named++;
        }
        for (String[] e : DATA) {
            Address a = toAddr(e[0]);
            createLabel(a, e[1], true, SourceType.USER_DEFINED);
            if (!e[2].isEmpty()) { setPlateComment(a, e[2]); commented++; }
        }
        println("labelled " + named + " functions and " + DATA.length + " data addresses ("
                + commented + " with comments)");
    }
}
