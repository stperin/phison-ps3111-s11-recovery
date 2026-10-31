#!/usr/bin/env python3
"""Read-only access to the Phison S11 vendor commands (SATAFIRM), on top of Psychite.

On the target (as root, with Psychite on PYTHONPATH):
    PYTHONPATH=/run/live/medium/live/psychite/src python3 safe_dump.py /dev/sg0 sysinfo
Streaming dump back to your workstation:
    ssh user@target 'sudo PYTHONPATH=... python3 safe_dump.py /dev/sg0 dump ... --out -' \
        | python3 safe_dump.py - receive OUTDIR

Safety: every ATA command goes through SafeDrive.command, which permits only
  - IDENTIFY DEVICE;
  - STANDBY IMMEDIATE carrying the AP key (count 0x6F, LBA 0xFAEFFE), which arms one vendor command;
  - READ/WRITE SECTORS NO RETRY immediately after that key, with a VUC feature on the allowlist.
Writes (SET_PARAMETER included) are refused until a valid SystemInfo has been read in this session:
that is the proof the firmware is intercepting vendor commands, without which a write would land
on a real LBA. Unlock and DOWNLOAD MICROCODE (engineering header only) need explicit flags.
Every command is recorded in a JSONL log.
"""

import argparse
import dataclasses
import enum
import json
import os
import pathlib
import struct
import sys
import time
from typing import BinaryIO

SECTOR_SIZE = 512

# Dump stream: page record, end of block, end of stream
PAGE_HEADER = struct.Struct("<4sBBHHBBII")  # magic, ce, die, block, page, flags, status, data_len, oob_len
BLOCK_DONE = struct.Struct("<4sBBH")  # magic, ce, die, block
MAGIC_PAGE = b"S11P"
MAGIC_BLOCK = b"S11B"
MAGIC_END = b"S11E"
FLAG_PSLC = 1
STATUS_OK = 0
STATUS_ERROR = 1
STATUS_SKIPPED = 2


class Blocked(Exception):
    """Command refused by the safety filter."""


def _open_drive(args: argparse.Namespace):
    # imported here: receive/done-list run on the workstation, without Psychite
    import ctypes

    if not hasattr(ctypes, "_CData"):  # Python < 3.14: Psychite refers to it in annotations
        ctypes._CData = ctypes._SimpleCData.__mro__[1]

    from phison_s11 import drive as s11_drive
    from phison_s11 import firmware as s11_firmware
    from phison_s11 import system_info as s11_system_info
    from phison_s11.ata import command as ata_command
    from phison_s11.ata import drive as ata_drive

    F = s11_drive.VUCFeature
    C = ata_command.Command

    ap_key = (0x6F, 0xFAEFFE)
    vuc_read = {
        F.READ_FLASH,
        F.READ_SRAM,
        F.SYSTEM_INFO,
        F.FLASH_ID,
        F.FLASH_ID_ALL,
        F.READ_INFO_BLOCK,
        F.READ_REGISTER,
        F.ONFI_PARAMETER_PAGE,
        F.MAX_BAD_PER_PLANE,
        F.READ_PRODUCT_HISTORY,
        F.BLOCK_MAP,
    }
    vuc_write = {F.SET_PARAMETER}
    vuc_unlock_read = {F.VUC_UNLOCK_READ}
    # reading the installed firmware (read_firmware.py): SEND_SEED sets the output encryption key in RAM
    vuc_fw_read = {F.VERIFY_FLASH}
    vuc_fw_write = {F.SEND_SEED}
    vuc_unlock_write = {F.VUC_UNLOCK_START, F.VUC_UNLOCK_WRITE, F.VUC_LOCK}
    engineering_header = bytes(s11_firmware.Header(engineering_mode=True))

    def _refuse(name: str):
        def method(self, *a, **k):
            raise Blocked(f"{name} not permitted")

        return method

    class SafeDrive(s11_drive.Drive):
        def __init__(self, path: pathlib.Path, log: BinaryIO, errors_only: bool = False) -> None:
            # no automatic vuc_unlock(), unlike s11_drive.Drive.__init__
            ata_drive.Drive.__init__(self, path)
            self._log = log
            self._log_errors_only = errors_only
            self._log_warned = False
            self._armed = False
            self.vuc_verified = False
            # TODO: several cmd_* raise and lower these by hand (allow_x = True, operation,
            # allow_x = False) with no try/finally -- clear-protect, update-firmware, engineering,
            # unlock, read-firmware. If the operation raises, the flag stays raised for the rest of
            # the process and the filter is more permissive than anyone expects. erase-block and
            # restart do use try/finally, so the problem is known but not handled systematically.
            # A context manager (with drive.allowing("erase"): ...) would make it impossible to forget.
            self.allow_unlock = False
            self.allow_engineering_dlmc = False
            self.allow_fw_read = False
            self.allow_write_register = False  # writes to controller RAM/registers (volatile, no NAND)
            self.allow_restart = False  # soft controller reset (volatile)
            self.allow_erase = False  # ERASE of a NAND block: IRREVERSIBLE, only from cmd_erase_block
            self.allow_dlmc_data: bytes | None = None  # the only firmware allowed for segmented DOWNLOAD MICROCODE
            self.sysinfo_raw: bytes | None = None

        def _check(self, r, data) -> None:
            is_write = isinstance(data, (bytes, bytearray))
            armed, self._armed = self._armed, False
            cmd = r.command

            if cmd == C.IDENTIFY_DEVICE and not is_write:
                return
            if cmd == C.STANDBY_IMMEDIATE and (r.count, r.lba) == ap_key and not data:
                self._armed = True
                return
            if cmd in (C.READ_SECTORS_NO_RETRY, C.WRITE_SECTORS_NO_RETRY):
                if not armed:
                    raise Blocked(f"{C(cmd).name} without the AP key")
                feat = r.feature
                if cmd == C.READ_SECTORS_NO_RETRY and not is_write:
                    if (
                        feat in vuc_read
                        or (self.allow_unlock and feat in vuc_unlock_read)
                        or (self.allow_fw_read and feat in vuc_fw_read)
                    ):
                        return
                if cmd == C.WRITE_SECTORS_NO_RETRY and is_write:
                    if not self.vuc_verified:
                        raise Blocked("VUC write before a valid SystemInfo")
                    if (
                        feat in vuc_write
                        or (self.allow_unlock and feat in vuc_unlock_write)
                        or (self.allow_fw_read and feat in vuc_fw_write)
                        or (self.allow_write_register and feat == F.WRITE_REGISTER)
                        or (self.allow_restart and feat == F.RESTART)
                        or (self.allow_erase and feat == F.ERASE_FLASH)
                    ):
                        return
                raise Blocked(f"VUC feature {feat:#x} not permitted ({C(cmd).name})")
            if (
                cmd == C.DOWNLOAD_MICROCODE
                and self.allow_engineering_dlmc
                and r.feature == ata_command.DLMCSubcommand.FULL
                and is_write
                and bytes(data) == engineering_header
            ):
                return
            # TODO: `in` is a substring search, not a positional comparison: it admits any chunk that
            # appears anywhere in the approved firmware, in any order and any number of times. We promise
            # "only this firmware" and enforce "bytes present in this firmware", which is the weakest
            # point of the filter. Keep a cursor of the expected offset and require each segment to be
            # the next one.
            if (
                cmd == C.DOWNLOAD_MICROCODE
                and self.allow_dlmc_data is not None
                and r.feature == ata_command.DLMCSubcommand.SEGMENTED
                and is_write
                and bytes(data) in self.allow_dlmc_data
            ):
                return
            name = C(cmd).name if cmd in C._value2member_map_ else hex(cmd)
            raise Blocked(f"ATA command {name} not permitted")

        def command(self, registers, data=None, dma=False, extend=False, timeout=30):
            entry = {
                "t": round(time.time(), 3),
                "cmd": hex(registers.command),
                "feat": hex(registers.feature),
                "count": registers.count,
                "lba": hex(registers.lba),
                "dir": "out" if isinstance(data, (bytes, bytearray)) else "in",
                "size": len(data) if isinstance(data, (bytes, bytearray)) else (data or 0),
            }
            try:
                self._check(registers, data)
            except Blocked as e:
                entry["blocked"] = str(e)
                self._write_log(entry)
                raise
            t0 = time.monotonic()
            try:
                result = super().command(registers, data, dma, extend, timeout)
            except Exception as e:
                entry["ms"] = round((time.monotonic() - t0) * 1000, 1)
                entry["error"] = repr(e)
                self._write_log(entry)
                raise
            entry["ms"] = round((time.monotonic() - t0) * 1000, 1)
            if not self._log_errors_only:
                self._write_log(entry)
            return result

        def _write_log(self, entry: dict) -> None:
            # a log that cannot be written (a full disk, say) must not stop the work
            try:
                self._log.write((json.dumps(entry) + "\n").encode())
                self._log.flush()
            except OSError as e:
                if not self._log_warned:
                    print(f"warning: log not writable: {e}", file=sys.stderr)
                    self._log_warned = True

        def vuc_system_info(self):
            data = self.vuc(F.SYSTEM_INFO, s11_system_info.SystemInfo.SIZE)
            info = s11_system_info.SystemInfo.from_bytes(data)  # ValueError if it is not a SystemInfo
            self.sysinfo_raw = data
            self.vuc_verified = True
            return info

        def _vuc_flash_set_parameter(self, ce_index, die, block, page, system_info):
            """As Psychite does it, but with the correct encoding of the CE byte.

            Psychite uses the bit position within ce_bitmap (0/4/8/12). On the target the byte is
            (channel << 3) | (extra_page << 1) | ce_within_channel: 4 and 12 silently re-read CE0/CE1
            at page+2. Bitmap address a -> byte ((a >> 2) & 1) << 3 | ((a >> 3) & 1): 0->0, 4->8,
            8->1, 12->9. Verified against the CE id in the OOB (byte 10 = bitmap address).
            """
            system_info = system_info or self.vuc_system_info()
            address = self._ce_address(ce_index, system_info)
            ce_raw = (((address >> 2) & 1) << 3) | ((address >> 3) & 1)
            if not system_info.dies_per_ce or die >= system_info.dies_per_ce:
                raise ValueError("Invalid die", die)
            if not system_info.blocks_per_die or block >= system_info.blocks_per_die:
                raise ValueError("Invalid block", block)
            if not system_info.pages_per_block or page >= system_info.pages_per_block:
                raise ValueError("Invalid page", page)
            block_address = die * (system_info.die_stride or 0) + block
            self.vuc_set_parameter(struct.pack("<20xBxHH", ce_raw, block_address, page))

        def read_page(self, ce, die, block, page, pslc, info):
            """Raw page: (data, 512-byte OOB). Like vuc_read_flash but with the whole OOB."""
            self._vuc_flash_set_parameter(ce, die, block, page, info)
            data_size = info.sectors_per_page * SECTOR_SIZE
            # bit 16: parameter format; 15: pSLC; 0: whole page.
            # Bit 13 ("OOB only" per Psychite) returns the first data sector on this target, not the OOB.
            lba = (1 << 16) | (int(pslc) << 15) | 1
            raw = self.vuc(F.READ_FLASH, data_size + SECTOR_SIZE, lba)
            return raw[:data_size], raw[data_size:]

        def vuc_write_register(self, address, data):
            # write to controller RAM/registers: volatile, no NAND write; only with allow_write_register
            if not self.allow_write_register:
                raise Blocked("vuc_write_register not permitted")
            return s11_drive.Drive.vuc_write_register(self, address, data)

        def vuc_restart(self):
            # soft controller reset: volatile, no NAND write; only with allow_restart
            if not self.allow_restart:
                raise Blocked("vuc_restart not permitted")
            return s11_drive.Drive.vuc_restart(self)

        def vuc_erase_flash(self, ce_index, die, block, pslc, system_info=None):
            # ERASE of a NAND block: irreversible. Only with allow_erase, which cmd_erase_block sets
            # after checking the page-0 magic and the presence of the local backup.
            if not self.allow_erase:
                raise Blocked("vuc_erase_flash not permitted")
            return s11_drive.Drive.vuc_erase_flash(self, ce_index, die, block, pslc, system_info)

        vuc_write_flash = _refuse("vuc_write_flash")
        vuc_write_info_block = _refuse("vuc_write_info_block")
        vuc_program_pram = _refuse("vuc_program_pram")
        vuc_program_pram_icode = _refuse("vuc_program_pram_icode")
        vuc_jump = _refuse("vuc_jump")
        cmd_write_log_ext = _refuse("cmd_write_log_ext")

    log = open(args.log, "ab")
    return SafeDrive(pathlib.Path(args.drive), log, args.log_errors_only)


def _jsonable(value):
    if dataclasses.is_dataclass(value):
        return {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.name
    if isinstance(value, (list, tuple)):
        return [_jsonable(x) for x in value]
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    return str(value)


def _print(obj) -> None:
    print(json.dumps(_jsonable(obj), indent=2))


def _parse_range(spec: str, limit: int) -> list[int]:
    if spec == "all":
        return list(range(limit))
    out: list[int] = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        # TODO: a reversed range ("100-50") silently yields an empty list instead of an error, and the
        # dump then reads nothing without saying why. It should be reported.
        out.extend(range(int(a), int(b or a) + 1))
    if any(not 0 <= x < limit for x in out):
        raise SystemExit(f"range {spec} outside 0..{limit - 1}")
    return out


def cmd_identify(drive, args) -> None:
    _print(drive.cmd_identify_device())


def cmd_sysinfo(drive, args) -> None:
    info = drive.vuc_system_info()
    if args.raw:
        pathlib.Path(args.raw).write_bytes(drive.sysinfo_raw)
    _print(info)


def cmd_info_block(drive, args) -> None:
    drive.vuc_system_info()
    from phison_s11 import drive as s11_drive
    from phison_s11 import info_block as s11_info_block

    data = drive.vuc(s11_drive.VUCFeature.READ_INFO_BLOCK, s11_info_block.InfoBlock.SIZE)
    if args.raw:
        pathlib.Path(args.raw).write_bytes(data)
    _print(s11_info_block.InfoBlock.from_bytes(data))


def cmd_flash_id(drive, args) -> None:
    info = drive.vuc_system_info()
    _print([drive.vuc_flash_id(ce, info) for ce in range(info.ce_count)])


def cmd_block_map(drive, args) -> None:
    """Like vuc_block_map, but saves the raw data and accepts block types Psychite does not know."""
    from phison_s11 import drive as s11_drive

    info = drive.vuc_system_info()
    stride = info.die_stride or 0
    entries = (info.dies_per_ce - 1) * stride + info.blocks_per_die
    read_size = -(entries * 4 // -4096) * 4096
    known = {t.value: t.name for t in s11_drive.BlockType}
    result = {}
    for channel in range(info.channel_count):
        raw = drive.vuc(s11_drive.VUCFeature.BLOCK_MAP, read_size, channel << 8)
        if args.out:
            pathlib.Path(f"{args.out}.ch{channel}.bin").write_bytes(raw)
        values = struct.unpack_from(f"<{entries}L", raw)
        result[channel] = [
            [
                None if not x else [known.get(x & 0xFF, hex(x & 0xFF)), x >> 8]
                for x in values[die * stride : die * stride + info.blocks_per_die]
            ]
            for die in range(info.dies_per_ce)
        ]
    text = json.dumps(result)
    if args.out:
        pathlib.Path(args.out).write_text(text)
    for channel, dies in result.items():
        for die, entries in enumerate(dies):
            counts: dict[str, int] = {}
            for e in entries:
                key = "None" if e is None else e[0]
                counts[key] = counts.get(key, 0) + 1
            print(f"channel {channel} die {die}: {counts}")


def cmd_read_sram(drive, args) -> None:
    """Reads SRAM in chunks and saves each chunk immediately: some addresses hang the controller."""
    drive.vuc_system_info()
    with open(args.out, "wb") as f:
        for addr in range(args.address, args.address + args.size, args.chunk):
            data = drive.vuc_read_sram(addr, min(args.chunk, args.address + args.size - addr))
            f.write(data)
            f.flush()
            print(f"{addr:#x}: {len(data)} bytes, {sum(1 for c in data if c)} non-zero", file=sys.stderr)


def cmd_probe_ce(drive, args) -> None:
    """Reads (block, page) with a raw value for the CE byte in the READ_FLASH parameter.

    Psychite uses the bit position within ce_bitmap (0/4/8/12): 4 and 12 re-read CE0/CE2 at page+2.
    This is how you find the encoding that really selects CE1/CE3. A wrong value can hang the
    controller.
    """
    import hashlib

    from phison_s11 import drive as s11_drive

    info = drive.vuc_system_info()
    parameter = struct.pack("<20xBxHH", args.ce_raw, args.block, args.page)
    drive.vuc_set_parameter(parameter)
    lba = (1 << 16) | (int(args.pslc) << 15) | 1
    size = info.sectors_per_page * SECTOR_SIZE
    raw = drive.vuc(s11_drive.VUCFeature.READ_FLASH, size + SECTOR_SIZE, lba)
    data, oob = raw[:size], raw[size:]
    pidx = int.from_bytes(oob[14:16], "big") // 0x40
    print(f"ce_raw {args.ce_raw}: OOB index {pidx}, byte8 {oob[8]}, oob {oob[:16].hex()}, sha1 {hashlib.sha1(data).hexdigest()[:12]}")
    if args.out:
        pathlib.Path(args.out).write_bytes(data)
        pathlib.Path(args.out + ".oob").write_bytes(oob)


# Meaning of the protect-flag bits (0x5C0CB5F0), from the SBFM21.1 disassembly:
#   bit 0 -> FUN_6003bde8: NAND context +0xfec is non-zero
#   bit 1 -> FUN_60056864: state of a hardware pin/register (reg+0x31c bit 9), polarity from config
#   bit 2 -> FUN_60016c4c: the system-area scan found an "ERROR_UNIT" page
#   bit 3 -> read together with bit 2 by FUN_6000892c; the setter is not in the decompiled functions
PROTECT_BITS = {
    0: "bit0: invalid NAND context (FUN_6003bde8)",
    1: "bit1: hardware pin/register (FUN_60056864)",
    2: "bit2: ERROR_UNIT or erased page in the system area (FUN_60016c4c)",
    3: "bit3: unknown condition, consumed together with bit2 (FUN_6000892c)",
}

# Diagnostic variables written by the init scan FUN_60016c4c.
# (address, size, description). All in IRAM/SRAM: read-only, no NAND.
DIAG_VARS = [
    (0x5C0CB5F0, 1, "protect flag (bitfield)"),
    (0x5C0CEAAC, 1, "block where the scan saw ERROR_UNIT"),
    (0x5C0CE6DA, 1, "block of the SYSTEM_UNIT_HEADER found (0xff = none)"),
    (0x5C0CE6DB, 1, "block of the BLOCK_MAP found (0xff = none)"),
    (0x5C0CE9AB, 1, "scan block limit (starts at 100)"),
    (0x5C0CE6B4, 1, "CE count"),
    (0x5C0CEAE8, 4, "CE bitmap"),
    (0x5C0CA0E0, 2, "counters: SYSTEM_UNIT_HEADER, BLOCK_MAP"),
    (0x5C0CE6EE, 1, "geometry-initialised flag"),
]
DIAG_SRAM = [
    (0x6005CD40, 8, "SYSTEM_UNIT_HEADER block array"),
    (0x6005CD00, 8, "BLOCK_MAP block array"),
    (0x6005CD10, 32, "sequence number array (u32)"),
    (0x50001200, 0x400, "the scan's OOB buffer (4 slots of 0x100)"),
]

# Magics of the first OOB u32, as FUN_60016c4c and the rest of the firmware classify them.
PAGE_MAGIC = {
    0xFFA00000: "SYSTEM_UNIT_HEADER",
    0x3FB10200: "BLOCK_MAP",
    0x3FB10400: "PRODUCT_HISTORY",
    0x44505354: "SYSTEM_UNIT_DATA",
    0x31113111: "FIRMWARE_HEADER",
    0x55AA55AA: "FIRMWARE_CODE",
}
ERROR_UNIT_MASK = 0xFFD00000


def classify_oob_header(value: int) -> str:
    """Classifies the first OOB u32 by the same rules the firmware uses.

    The ERROR_UNIT test is a mask, not a comparison: (~v & 0xFFD00000) == 0. So 0xFFFFFFFF (an
    erased page, or an uncorrectable read) falls into the same branch and sets bit 2 of the
    protect flag.
    """
    if (~value & ERROR_UNIT_MASK & 0xFFFFFFFF) == 0:
        return "ERROR_UNIT (erased)" if value == 0xFFFFFFFF else "ERROR_UNIT"
    if value in PAGE_MAGIC:
        return PAGE_MAGIC[value]
    return f"LBA {value:#x}"


def cmd_diag_protect(drive, args) -> None:
    """Reads the variables the init scan leaves in RAM. Read-only, no writes.

    FUN_60016c4c walks page 0 of blocks 0..limit on every CE, classifies the first OOB u32 and
    records what it found. Reading these variables tells you *why* the drive is in protect mode and
    which block it tripped over, with no diagnostic loader needed.
    """
    drive.vuc_system_info()
    identify = drive.cmd_identify_device()
    print(f"IDENTIFY model={identify.model!r} firmware={identify.firmware!r}")
    for address, size, label in DIAG_VARS:
        data = drive.vuc_read_register(address, size)
        print(f"{address:#010x} [{size}] {data.hex():<8} {label}")
        if address == 0x5C0CB5F0 and size == 1:
            bits = [text for bit, text in PROTECT_BITS.items() if data[0] >> bit & 1]
            extra = [f"bit{b}" for b in range(4, 8) if data[0] >> b & 1]
            print(f"    flag = {data[0]:#04x}: " + ("; ".join(bits + extra) or "no bits set"))
    if not args.sram:
        return
    for address, size, label in DIAG_SRAM:
        data = drive.vuc_read_sram(address, size)
        print(f"{address:#010x} [{size}] {label}")
        for off in range(0, size, 32):
            print(f"    +{off:#05x} {data[off:off + 32].hex()}")


def cmd_sys_scan(drive, args) -> None:
    """Re-reads page 0 of the system blocks the way the init scan does, and classifies it.

    This is how you find the page the firmware reads as an ERROR_UNIT. Read-only.
    The read mode matters: a pSLC block read in MLC mode looks erased, i.e. 0xffffffff, which is
    exactly the value that trips protect mode. Try both modes.
    """
    info = drive.vuc_system_info()
    out = open(args.out, "w") if args.out else None
    for ce in _parse_range(args.ce, info.ce_count):
        for block in _parse_range(args.blocks, info.blocks_per_die):
            try:
                _data, oob = drive.read_page(ce, args.die, block, 0, args.pslc, info)
            except Exception as exc:  # an unreadable page must not stop the scan
                line = f"ce {ce} block {block:4d}: error {exc}"
            else:
                value = struct.unpack_from("<I", oob, 0)[0]
                seq = struct.unpack_from("<I", oob, 4)[0]
                line = (f"ce {ce} block {block:4d}: {value:08x} {classify_oob_header(value):<26}"
                        f" seq {seq & 0xFFFFFF:#08x} ecc {oob[8]:#04x} ce_id {oob[10]:#04x}")
            print(line, flush=True)
            if out:
                out.write(line + "\n")
                out.flush()
    if out:
        out.close()


def cmd_product_history(drive, args) -> None:
    """Reads the product history (VUC 0xDA, read-only).

    On these controllers it typically holds the lifetime counters: power cycles, hours, and in
    particular unexpected power losses. Useful for establishing the cause behind the failure.
    """
    from phison_s11 import drive as s11_drive

    drive.vuc_system_info()
    data = drive.vuc(s11_drive.VUCFeature.READ_PRODUCT_HISTORY, args.size)
    print(f"{len(data)} bytes")
    if args.out:
        pathlib.Path(args.out).write_bytes(data)
    for off in range(0, min(len(data), args.show), 16):
        chunk = data[off:off + 16]
        ascii_ = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"  +{off:04x} {chunk.hex(' ')}  {ascii_}")


def cmd_restart(drive, args) -> None:
    """Soft controller reset: reloads the sections from NAND and re-runs the init scan.

    Volatile, no NAND write. Needed after erasing the error unit: an S3 suspend is only a COMRESET,
    whereas the `FUN_60016c4c` scan runs on a controller reset.
    """
    drive.vuc_system_info()
    before = drive.vuc_read_register(0x5C0CB5F0, 1)
    ident0 = drive.cmd_identify_device()
    print(f"before: flag={before.hex()}, IDENTIFY model={ident0.model!r} firmware={ident0.firmware!r}")
    drive.allow_restart = True
    try:
        drive.vuc_restart()
    except Exception as e:
        raise SystemExit(f"reset: {e!r} (the controller may have hung; recover with S3 + rescan)")
    finally:
        drive.allow_restart = False
    for address, size, label in DIAG_VARS:
        data = drive.vuc_read_register(address, size)
        print(f"{address:#010x} [{size}] {data.hex():<8} {label}")
        if address == 0x5C0CB5F0 and size == 1:
            bits = [text for bit, text in PROTECT_BITS.items() if data[0] >> bit & 1]
            print(f"    flag = {data[0]:#04x}: " + ("; ".join(bits) or "NO BITS SET: protect mode is off"))
    ident = drive.cmd_identify_device()
    print(f"after:  IDENTIFY model={ident.model!r} firmware={ident.firmware!r}")


def cmd_erase_block(drive, args) -> None:
    """Erases a NAND block. IRREVERSIBLE. Meant for the error unit holding the drive in protect mode.

    Three interlocks before anything is written:
      1. page 0 of the block must carry the expected magic (default: the ERROR_UNIT mask), read
         through the same addressing the erase will use, so it really is that block;
      2. a complete local backup of the block must exist (data + OOB), passed with --backup;
      3. --yes is required.
    After the erase it re-reads page 0 and prints how it came back.
    """
    info = drive.vuc_system_info()
    data, oob = drive.read_page(args.ce, args.die, args.block, 0, args.pslc, info)
    value = struct.unpack_from("<I", oob, 0)[0]
    kind = classify_oob_header(value)
    print(f"ce {args.ce} die {args.die} block {args.block}: page 0 word0 = {value:#010x} ({kind})")
    print(f"  page 0 of this read: OOB byte8 = {oob[8]:#04x}")

    if args.expect == "error-unit":
        if (~value & ERROR_UNIT_MASK & 0xFFFFFFFF) != 0:
            raise SystemExit(f"INTERLOCK 1: page 0 is not an ERROR_UNIT ({value:#010x}), nothing erased")
    elif args.expect != "any":
        if value != int(args.expect, 0):
            raise SystemExit(f"INTERLOCK 1: word0 {value:#010x} != {args.expect}, nothing erased")

    backup = pathlib.Path(args.backup)
    bo = backup.with_suffix(".oob")
    if not (backup.exists() and bo.exists()):
        raise SystemExit(f"INTERLOCK 2: backup missing ({backup} / {bo}), nothing erased")
    saved = bo.read_bytes()
    if struct.unpack_from("<I", saved, 0)[0] != value:
        raise SystemExit("INTERLOCK 2: the backup does not match this block, nothing erased")
    print(f"  backup: {backup} ({backup.stat().st_size} B) + OOB ({len(saved)} B), word0 matches")

    if not args.yes:
        raise SystemExit("--yes missing: nothing erased")

    drive.allow_erase = True
    try:
        drive.vuc_erase_flash(args.ce, args.die, args.block, args.pslc, info)
    finally:
        drive.allow_erase = False
    print("  ERASE done")

    _data, oob2 = drive.read_page(args.ce, args.die, args.block, 0, args.pslc, info)
    v2 = struct.unpack_from("<I", oob2, 0)[0]
    print(f"  after: word0 = {v2:#010x} ({classify_oob_header(v2)}), OOB byte8 = {oob2[8]:#04x}")
    print(f"  page 0 OOB: {oob2[:16].hex()}")


def cmd_clear_protect(drive, args) -> None:
    """Zeroes the protect-mode flag in RAM (0x5C0CB5F0). A volatile write to the controller, no NAND.

    A diagnostic test: if IDENTIFY then reports the normal model and `dd if=/dev/sdX` reads real
    data, the FTL was already mounted; if it reads zeros, the boot has to be re-run.
    """
    PROTECT_FLAG_ADDR = 0x5C0CB5F0
    drive.vuc_system_info()
    before = drive.cmd_identify_device()
    cur = drive.vuc_read_register(PROTECT_FLAG_ADDR, 1)
    print(f"before: IDENTIFY model={before.model!r} firmware={before.firmware!r}; flag={cur.hex()}")
    if not args.yes:
        raise SystemExit("--yes missing: nothing written")
    drive.allow_write_register = True
    drive.vuc_write_register(PROTECT_FLAG_ADDR, b"\x00")
    drive.allow_write_register = False
    now = drive.vuc_read_register(PROTECT_FLAG_ADDR, 1)
    after = drive.cmd_identify_device()
    print(f"after:  IDENTIFY model={after.model!r} firmware={after.firmware!r}; flag={now.hex()}")


def cmd_probe_reset_patch(drive, args) -> None:
    """Patches the instruction that sets protect mode (0x60017003) in RAM and tests whether it
    survives a reset.

    Original: s8i a9,a10,0 (92 4a 00) writes flag|4. Patch: or a9,a9,a9 (90 99 20) = no-op.
    A volatile write to controller SRAM, no NAND. With --restart it performs a soft reset and
    re-reads: if the bytes stay patched, RAM survives the reset (an in-place route is viable); if
    they revert, the reset reloads from NAND (ROM mode would be needed).
    """
    ADDR = 0x60017003
    ORIG = bytes.fromhex("924a00")
    PATCH = bytes.fromhex("909920")
    FLAG = 0x5C0CB5F0
    drive.vuc_system_info()
    cur = drive.vuc_read_register(ADDR, 3)
    print(f"instruction at {ADDR:#x}: {cur.hex()} ({'original' if cur == ORIG else 'already patched' if cur == PATCH else 'SOMETHING ELSE'})")
    if cur not in (ORIG, PATCH):
        raise SystemExit("the bytes do not match what was expected: touching nothing")
    if not args.yes:
        raise SystemExit("--yes missing: nothing written")
    drive.allow_write_register = True
    # WRITE_REGISTER writes aligned 4-byte words: patch by read-modify-write over the two words involved
    base = ADDR & ~3  # 0x60017000
    span = bytearray(drive.vuc_read_register(base, 8))  # covers 0x60017000..0x60017007
    off = ADDR - base  # 3
    span[off : off + 3] = PATCH
    drive.vuc_write_register(base, bytes(span[0:4]))
    drive.vuc_write_register(base + 4, bytes(span[4:8]))
    back = drive.vuc_read_register(ADDR, 3)
    print(f"after patch: {back.hex()} ({'ok' if back == PATCH else 'WRITE FAILED'})")
    drive.allow_write_register = False
    if back != PATCH:
        raise SystemExit("the SRAM write did not take: WRITE_REGISTER does not reach this region")
    if not args.restart:
        print("patch applied in RAM; without --restart no reset is performed")
        return
    print("performing a soft reset...")
    drive.allow_restart = True
    try:
        drive.vuc_restart()
    except Exception as e:
        drive.allow_restart = False
        raise SystemExit(f"reset: {e!r} (the controller may have hung; recover with S3 + rescan)")
    drive.allow_restart = False
    after = drive.vuc_read_register(ADDR, 3)
    flag = drive.vuc_read_register(FLAG, 1)
    ident = drive.cmd_identify_device()
    survived = after == PATCH
    print(f"after reset: instruction {after.hex()} -> RAM {'SURVIVED' if survived else 'reloaded from NAND'}")
    print(f"             protect flag={flag.hex()}, IDENTIFY model={ident.model!r} firmware={ident.firmware!r}")


def cmd_read_firmware(drive, args) -> None:
    """Extracts the installed firmware (Psychite's example/read_firmware.py): SEND_SEED + VERIFY_FLASH."""
    import importlib.util

    from phison_s11 import drive as s11_drive
    from phison_s11 import flash as s11_flash

    drive.vuc_system_info()
    drive.allow_fw_read = True
    path = pathlib.Path(args.psychite_example) / "read_firmware.py"
    spec = importlib.util.spec_from_file_location("psychite_read_firmware", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if args.raw:
        # raw data, before any interpretation: flash header + sections exactly as the drive returns them
        from phison_s11 import firmware as s11_firmware

        seed = s11_firmware.Seed()
        drive.vuc_send_seed(seed)
        header_raw = drive.vuc(s11_drive.VUCFeature.VERIFY_FLASH, s11_flash.FirmwareHeader.SIZE)
        header = s11_flash.FirmwareHeader.from_bytes(header_raw)
        pathlib.Path(args.out + ".header").write_bytes(header_raw)
        print(f"header: {header}")
        for i, section in enumerate(x for x in header.sections if x):
            data = bytearray()
            while len(data) < section.size:
                data += drive.vuc(s11_drive.VUCFeature.VERIFY_FLASH, min(section.size - len(data), 0x10000), 1 << 16)
            pathlib.Path(f"{args.out}.sec{i}").write_bytes(data)
            print(f"section {i}: {section} -> {len(data)} bytes")
        return
    firmware = module.read_firmware(drive)
    data = bytes(firmware)
    pathlib.Path(args.out).write_bytes(data)
    print(f"firmware: {firmware}")
    print(f"saved {args.out}: {len(data)} bytes")


def cmd_update_firmware(drive, args) -> None:
    """Segmented DOWNLOAD MICROCODE of a single file, checked by SHA-256 and by Psychite. Writes to the drive."""
    import hashlib

    from phison_s11 import firmware as s11_firmware

    data = pathlib.Path(args.firmware).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.sha256:
        raise SystemExit(f"SHA-256 {digest} does not match the expected one")
    firmware = s11_firmware.Firmware.from_bytes(data)  # checks the structure and the section CRCs
    info = drive.vuc_system_info()
    print(f"before: {drive.cmd_identify_device().firmware}, protected_mode {info.protected_mode}")
    print(f"loading: {firmware.version} {firmware.date}")
    if not args.yes:
        raise SystemExit("--yes missing: nothing written")
    drive.allow_dlmc_data = data
    drive.cmd_download_microcode_segmented(data)
    drive.allow_dlmc_data = None
    print(f"after: IDENTIFY firmware {drive.cmd_identify_device().firmware}")


def cmd_engineering(drive, args) -> None:
    """DOWNLOAD MICROCODE mode 7 with only the engineering header (per Psychite: changes mode, writes no firmware)."""
    from phison_s11 import firmware as s11_firmware

    before = drive.vuc_system_info()
    print(f"before: vuc_mode {before.vuc_mode}, protected_mode {before.protected_mode}")
    if not args.yes:
        raise SystemExit("--yes missing: no command sent")
    drive.allow_engineering_dlmc = True
    drive.cmd_download_microcode_full(bytes(s11_firmware.Header(engineering_mode=True)))
    drive.allow_engineering_dlmc = False
    after = drive.vuc_system_info()
    print(f"after: vuc_mode {after.vuc_mode}, protected_mode {after.protected_mode}, IDENTIFY {drive.cmd_identify_device().firmware}")


def cmd_unlock(drive, args) -> None:
    drive.allow_unlock = True
    drive.allow_engineering_dlmc = args.allow_engineering_dlmc
    before = drive.vuc_system_info().vuc_mode
    drive.vuc_unlock()
    after = drive.vuc_system_info().vuc_mode
    print(f"vuc_mode: {before} -> {after}")


def cmd_read_page(drive, args) -> None:
    info = drive.vuc_system_info()
    data, oob = drive.read_page(args.ce, args.die, args.block, args.page, args.pslc, info)
    if args.out:
        pathlib.Path(args.out).write_bytes(data)
        pathlib.Path(args.out + ".oob").write_bytes(oob)
    print(f"data {len(data)} B, OOB: {oob[:32].hex()}")


def cmd_dump(drive, args) -> None:
    info = drive.vuc_system_info()
    # plan (a file, or -): "skip ce die block", "skippage ce die block page", "only ce die block"
    skip: set[tuple[int, int, int]] = set()
    skip_pages: set[tuple[int, int, int, int]] = set()
    only: list[tuple[int, int, int]] = []
    if args.plan:
        src = sys.stdin if args.plan == "-" else open(args.plan)
        for line in src:
            # TODO: malformed numbers in the plan surface as an int() traceback rather than a message
            # naming the line. dump_runner writes the plan, but it also gets edited by hand.
            kind, *nums = line.split() or [""]
            if kind == "skip":
                skip.add(tuple(map(int, nums)))
            elif kind == "skippage":
                skip_pages.add(tuple(map(int, nums)))
            elif kind == "only":
                only.append(tuple(map(int, nums)))
            elif kind:
                raise SystemExit(f"invalid plan line: {line!r}")
    out = sys.stdout.buffer if args.out == "-" else open(args.out, "ab")
    flags = FLAG_PSLC if args.pslc else 0
    pages = _parse_range(args.pages, info.pages_per_block)
    if only:
        targets = only
    else:
        targets = [
            (ce, die, block)
            for ce in _parse_range(args.ce, info.ce_count)
            for die in _parse_range(args.die, info.dies_per_ce)
            for block in _parse_range(args.blocks, info.blocks_per_die)
        ]
    consecutive_errors = 0
    t0 = time.monotonic()
    n_pages = 0
    for ce, die, block in targets:
        if (ce, die, block) in skip:
            continue
        for page in pages:
            fatal = False
            if (ce, die, block, page) in skip_pages:
                data, oob, status = b"skipped: it had hung the controller", b"", STATUS_SKIPPED
            else:
                try:
                    data, oob = drive.read_page(ce, die, block, page, args.pslc, info)
                    status = STATUS_OK
                    consecutive_errors = 0
                except Blocked:
                    raise
                except OSError as e:
                    data, oob, status = repr(e).encode(), b"", STATUS_ERROR
                    consecutive_errors += 1
                    # only an ATA error (uncorrectable ECC, say) is tolerated; a timeout, ABORTED_COMMAND
                    # or an SG_IO error means the controller has hung, and any further command makes it worse
                    fatal = "ATA command failed" not in str(e)
            out.write(PAGE_HEADER.pack(MAGIC_PAGE, ce, die, block, page, flags, status, len(data), len(oob)))
            out.write(data)
            out.write(oob)
            n_pages += 1
            if fatal or consecutive_errors >= args.max_errors:
                out.flush()
                # line parsed by dump_runner.py
                print(f"FATAL {ce} {die} {block} {page}", file=sys.stderr)
                raise SystemExit(f"stopping at ce {ce} die {die} block {block} page {page}: {data.decode()}")
        out.write(BLOCK_DONE.pack(MAGIC_BLOCK, ce, die, block))
        out.flush()
        rate = n_pages / max(time.monotonic() - t0, 1e-6)
        # NOTE: dump_runner.py matches this line by its "block " prefix; keep both ends in step
        print(f"block ce {ce} die {die} {block} ok, {rate:.1f} pages/s", file=sys.stderr)
    out.write(MAGIC_END)
    out.flush()


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = stream.read(size - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def cmd_receive(args) -> None:
    """Receives the dump stream: one .data/.oob file per block, errors in .err, complete blocks in the manifest."""
    # TODO: the .part files are opened "wb" and os.replace promotes them at end of block. A second pass
    # over an already complete block, with a narrower page range, therefore replaces the complete file
    # with a partial one: silent loss. It does not happen in the normal flow, because dump_runner works
    # whole blocks and skips those in the manifest, but by hand it is one keystroke on a 105 GB dump.
    # Overwriting a block already in the manifest should be refused unless an explicit flag is given.
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = open(outdir / "manifest.txt", "a")
    stream = sys.stdin.buffer
    open_files: dict[tuple[int, int, int], tuple] = {}

    def files(ce, die, block):
        key = (ce, die, block)
        if key not in open_files:
            base = outdir / f"ce{ce}" / f"die{die}" / f"b{block:05d}"
            base.parent.mkdir(parents=True, exist_ok=True)
            open_files[key] = (
                base,
                open(f"{base}.data.part", "wb"),
                open(f"{base}.oob.part", "wb"),
                open(f"{base}.err.part", "w"),
            )
        return open_files[key]

    while True:
        try:
            magic = _read_exact(stream, 4)
        except EOFError:
            print("stream interrupted (the block in progress is discarded)", file=sys.stderr)
            break
        if magic == MAGIC_END:
            print("end of stream", file=sys.stderr)
            break
        if magic == MAGIC_PAGE:
            _, ce, die, block, page, flags, status, dlen, olen = PAGE_HEADER.unpack(
                magic + _read_exact(stream, PAGE_HEADER.size - 4)
            )
            data = _read_exact(stream, dlen)
            oob = _read_exact(stream, olen)
            _, fdata, foob, ferr = files(ce, die, block)
            if status == STATUS_OK:  # errors and skipped pages stay zero and go to .err
                fdata.seek(page * dlen)
                fdata.write(data)
                foob.seek(page * SECTOR_SIZE)
                foob.write(oob)
            else:
                ferr.write(json.dumps({"page": page, "flags": flags, "error": data.decode(errors="replace")}) + "\n")
        elif magic == MAGIC_BLOCK:
            _, ce, die, block = BLOCK_DONE.unpack(magic + _read_exact(stream, BLOCK_DONE.size - 4))
            base, *fs = files(ce, die, block)
            for f in fs:
                f.close()
            for ext in ("data", "oob", "err"):
                os.replace(f"{base}.{ext}.part", f"{base}.{ext}")
            del open_files[(ce, die, block)]
            manifest.write(f"{ce} {die} {block}\n")
            manifest.flush()
        else:
            raise SystemExit(f"corrupt stream: magic {magic!r}")


def cmd_done_list(args) -> None:
    path = pathlib.Path(args.outdir) / "manifest.txt"
    if path.exists():
        sys.stdout.write(path.read_text())


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("drive", help="the /dev/sgX device (ignored by receive/done-list: pass -)")
    p.add_argument("--log", default="safe_s11.log", help="JSONL log of every ATA command")
    p.add_argument("--log-errors-only", action="store_true", help="log only failures and blocked commands")
    sub = p.add_subparsers(dest="action", required=True)

    sub.add_parser("identify")
    s = sub.add_parser("sysinfo")
    s.add_argument("--raw")
    s = sub.add_parser("info-block")
    s.add_argument("--raw")
    sub.add_parser("flash-id")
    s = sub.add_parser("block-map")
    s.add_argument("--out")
    s = sub.add_parser("unlock", help="the VUC unlock sequence (writes controller status registers)")
    s.add_argument("--allow-engineering-dlmc", action="store_true", help="also permit DLMC with the engineering header alone")
    s = sub.add_parser("read-sram")
    s.add_argument("address", type=lambda x: int(x, 0))
    s.add_argument("size", type=lambda x: int(x, 0))
    s.add_argument("--chunk", type=lambda x: int(x, 0), default=0x1000)
    s.add_argument("--out", required=True)
    s = sub.add_parser("probe-ce")
    s.add_argument("ce_raw", type=int)
    s.add_argument("block", type=int)
    s.add_argument("page", type=int)
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--out")
    s = sub.add_parser("diag-protect", help="read the init scan's diagnostic variables (read-only)")
    s.add_argument("--sram", action="store_true", help="also read the arrays and the OOB buffer in SRAM")
    s = sub.add_parser("sys-scan", help="re-classify page 0 of the system blocks as init does (read-only)")
    s.add_argument("--ce", default="all")
    s.add_argument("--die", type=int, default=0)
    s.add_argument("--blocks", default="0-99")
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--out")
    s = sub.add_parser("product-history", help="read the controller's product history (read-only)")
    s.add_argument("--size", type=lambda x: int(x, 0), default=512)
    s.add_argument("--show", type=lambda x: int(x, 0), default=256)
    s.add_argument("--out")
    sub.add_parser("restart", help="soft controller reset: reload from NAND and re-run init (volatile)")
    s = sub.add_parser("erase-block", help="ERASES a NAND block (irreversible); meant for the error unit")
    s.add_argument("--ce", type=int, required=True)
    s.add_argument("--die", type=int, default=0)
    s.add_argument("--block", type=int, required=True)
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--expect", default="error-unit",
                   help="magic required in page 0: 'error-unit' (default), 'any', or a value like 0xffd00000")
    s.add_argument("--backup", required=True, help="the block's local .data backup (the matching .oob must exist too)")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("clear-protect", help="zero the protect flag in RAM (volatile write to the controller)")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("probe-reset-patch", help="patch the set-protect store in RAM and test whether it survives a reset")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--restart", action="store_true", help="after patching, perform a soft reset and re-read")
    s = sub.add_parser("read-firmware", help="extract the installed firmware (enables SEND_SEED and VERIFY_FLASH)")
    s.add_argument("--out", required=True)
    s.add_argument("--psychite-example", default="/run/live/medium/live/psychite/example")
    s.add_argument("--raw", action="store_true", help="save the header and sections raw, without interpreting them")
    s = sub.add_parser("update-firmware", help="segmented DOWNLOAD MICROCODE (WRITES to the drive)")
    s.add_argument("firmware")
    s.add_argument("--sha256", required=True)
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("engineering", help="engineering header via DOWNLOAD MICROCODE (no firmware written)")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("read-page")
    for name in ("ce", "die", "block", "page"):
        s.add_argument(name, type=int)
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--out")
    s = sub.add_parser("dump")
    s.add_argument("--ce", default="all")
    s.add_argument("--die", default="all")
    s.add_argument("--blocks", default="all", help="e.g. 0-99,200")
    s.add_argument("--pages", default="all", help="e.g. 0, or 0-1023")
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--plan", help="a file (or -) of 'skip|only ce die block' and 'skippage ce die block page' lines")
    s.add_argument("--max-errors", type=int, default=3, help="consecutive ATA (ECC) errors before giving up")
    s.add_argument("--out", required=True, help="output file, or - for stdout")
    s = sub.add_parser("receive")
    s.add_argument("outdir")
    s = sub.add_parser("done-list")
    s.add_argument("outdir")
    args = p.parse_args()

    if args.action == "receive":
        return cmd_receive(args)
    if args.action == "done-list":
        return cmd_done_list(args)

    handlers = {
        "identify": cmd_identify,
        "sysinfo": cmd_sysinfo,
        "info-block": cmd_info_block,
        "flash-id": cmd_flash_id,
        "block-map": cmd_block_map,
        "unlock": cmd_unlock,
        "read-page": cmd_read_page,
        "read-sram": cmd_read_sram,
        "probe-ce": cmd_probe_ce,
        "read-firmware": cmd_read_firmware,
        "update-firmware": cmd_update_firmware,
        "engineering": cmd_engineering,
        "diag-protect": cmd_diag_protect,
        "erase-block": cmd_erase_block,
        "restart": cmd_restart,
        "product-history": cmd_product_history,
        "sys-scan": cmd_sys_scan,
        "clear-protect": cmd_clear_protect,
        "probe-reset-patch": cmd_probe_reset_patch,
        "dump": cmd_dump,
    }
    drive = _open_drive(args)
    try:
        handlers[args.action](drive, args)
    except Blocked as e:
        raise SystemExit(f"BLOCKED: {e}")
    finally:
        drive.close()


if __name__ == "__main__":
    main()
