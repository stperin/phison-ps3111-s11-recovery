#!/usr/bin/env python3
"""Accesso in sola lettura ai VUC del Phison S11 (SATAFIRM), sopra Psychite.

Sul target (root, Psychite nel PYTHONPATH):
    PYTHONPATH=/run/live/medium/live/psychite/src python3 safe_dump.py /dev/sg0 sysinfo
Dump in streaming verso questo PC:
    ssh user@target 'sudo PYTHONPATH=... python3 safe_dump.py /dev/sg0 dump ... --out -' \
        | python3 safe_dump.py - receive OUTDIR

Sicurezza: ogni comando ATA passa da SafeDrive.command, che ammette solo
  - IDENTIFY DEVICE;
  - STANDBY IMMEDIATE con la AP key (count 0x6F, LBA 0xFAEFFE), che "arma" un solo VUC;
  - READ/WRITE SECTORS NO RETRY subito dopo la AP key, con feature VUC in allowlist.
Le write (anche SET_PARAMETER) sono ammesse solo dopo una SystemInfo valida nella sessione:
prova che il firmware intercetta i VUC, altrimenti la write finirebbe sull'LBA vero.
Unlock e DOWNLOAD MICROCODE (solo header engineering) richiedono flag espliciti.
Ogni comando è registrato in un log JSONL.
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

# Stream dump: record pagina, fine blocco, fine stream
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
    """Comando rifiutato dal filtro di sicurezza."""


def _open_drive(args: argparse.Namespace):
    # import qui: receive/done-list girano su questo PC senza Psychite
    import ctypes

    if not hasattr(ctypes, "_CData"):  # Python < 3.14: Psychite lo usa nelle annotazioni
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
    # lettura del firmware installato (read_firmware.py): SEND_SEED imposta la chiave di cifratura dell'output in RAM
    vuc_fw_read = {F.VERIFY_FLASH}
    vuc_fw_write = {F.SEND_SEED}
    vuc_unlock_write = {F.VUC_UNLOCK_START, F.VUC_UNLOCK_WRITE, F.VUC_LOCK}
    engineering_header = bytes(s11_firmware.Header(engineering_mode=True))

    def _refuse(name: str):
        def method(self, *a, **k):
            raise Blocked(f"{name} vietato")

        return method

    class SafeDrive(s11_drive.Drive):
        def __init__(self, path: pathlib.Path, log: BinaryIO, errors_only: bool = False) -> None:
            # niente vuc_unlock() automatico come in s11_drive.Drive.__init__
            ata_drive.Drive.__init__(self, path)
            self._log = log
            self._log_errors_only = errors_only
            self._log_warned = False
            self._armed = False
            self.vuc_verified = False
            self.allow_unlock = False
            self.allow_engineering_dlmc = False
            self.allow_fw_read = False
            self.allow_write_register = False  # scrittura in RAM/registri del controller (volatile, nessuna NAND)
            self.allow_restart = False  # soft reset del controller (volatile)
            self.allow_erase = False  # ERASE di un blocco NAND: IRREVERSIBILE, solo da cmd_erase_block
            self.allow_dlmc_data: bytes | None = None  # unico firmware ammesso per DOWNLOAD MICROCODE segmentato
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
                    raise Blocked(f"{C(cmd).name} senza AP key")
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
                        raise Blocked("write VUC prima di una SystemInfo valida")
                    if (
                        feat in vuc_write
                        or (self.allow_unlock and feat in vuc_unlock_write)
                        or (self.allow_fw_read and feat in vuc_fw_write)
                        or (self.allow_write_register and feat == F.WRITE_REGISTER)
                        or (self.allow_restart and feat == F.RESTART)
                        or (self.allow_erase and feat == F.ERASE_FLASH)
                    ):
                        return
                raise Blocked(f"VUC feature {feat:#x} non ammessa ({C(cmd).name})")
            if (
                cmd == C.DOWNLOAD_MICROCODE
                and self.allow_engineering_dlmc
                and r.feature == ata_command.DLMCSubcommand.FULL
                and is_write
                and bytes(data) == engineering_header
            ):
                return
            if (
                cmd == C.DOWNLOAD_MICROCODE
                and self.allow_dlmc_data is not None
                and r.feature == ata_command.DLMCSubcommand.SEGMENTED
                and is_write
                and bytes(data) in self.allow_dlmc_data
            ):
                return
            name = C(cmd).name if cmd in C._value2member_map_ else hex(cmd)
            raise Blocked(f"comando ATA {name} non ammesso")

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
            # un log che non si riesce a scrivere (es. disco pieno) non deve fermare il lavoro
            try:
                self._log.write((json.dumps(entry) + "\n").encode())
                self._log.flush()
            except OSError as e:
                if not self._log_warned:
                    print(f"avviso: log non scrivibile: {e}", file=sys.stderr)
                    self._log_warned = True

        def vuc_system_info(self):
            data = self.vuc(F.SYSTEM_INFO, s11_system_info.SystemInfo.SIZE)
            info = s11_system_info.SystemInfo.from_bytes(data)  # ValueError se non è SystemInfo
            self.sysinfo_raw = data
            self.vuc_verified = True
            return info

        def _vuc_flash_set_parameter(self, ce_index, die, block, page, system_info):
            """Come Psychite, ma con la codifica corretta del byte CE.

            Psychite usa la posizione del bit nella ce_bitmap (0/4/8/12). Sul target il byte è
            (canale << 3) | (pagina_extra << 1) | ce_nel_canale: con 4 e 12 si rileggevano CE0/CE1 a pagina+2.
            Indirizzo bitmap a -> byte ((a >> 2) & 1) << 3 | ((a >> 3) & 1): 0->0, 4->8, 8->1, 12->9.
            Verificato con l'id CE nell'OOB (byte 10 = indirizzo bitmap).
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
            """Pagina raw: (dati, OOB 512 byte). Come vuc_read_flash ma con l'OOB intero."""
            self._vuc_flash_set_parameter(ce, die, block, page, info)
            data_size = info.sectors_per_page * SECTOR_SIZE
            # bit 16: formato parametri; 15: pSLC; 0: pagina intera.
            # Il bit 13 ("solo OOB" secondo Psychite) sul target restituisce il primo settore di dati, non l'OOB.
            lba = (1 << 16) | (int(pslc) << 15) | 1
            raw = self.vuc(F.READ_FLASH, data_size + SECTOR_SIZE, lba)
            return raw[:data_size], raw[data_size:]

        def vuc_write_register(self, address, data):
            # scrittura in RAM/registri del controller: volatile, nessuna scrittura NAND; solo con allow_write_register
            if not self.allow_write_register:
                raise Blocked("vuc_write_register vietato")
            return s11_drive.Drive.vuc_write_register(self, address, data)

        def vuc_restart(self):
            # soft reset del controller: volatile, nessuna scrittura NAND; solo con allow_restart
            if not self.allow_restart:
                raise Blocked("vuc_restart vietato")
            return s11_drive.Drive.vuc_restart(self)

        def vuc_erase_flash(self, ce_index, die, block, pslc, system_info=None):
            # ERASE di un blocco NAND: irreversibile. Solo con allow_erase, che imposta cmd_erase_block
            # dopo aver verificato il magic della pagina 0 e l'esistenza del backup locale.
            if not self.allow_erase:
                raise Blocked("vuc_erase_flash vietato")
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
        out.extend(range(int(a), int(b or a) + 1))
    if any(not 0 <= x < limit for x in out):
        raise SystemExit(f"intervallo {spec} fuori da 0..{limit - 1}")
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
    """Come vuc_block_map, ma salva il raw e accetta tipi di blocco sconosciuti a Psychite."""
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
            print(f"canale {channel} die {die}: {counts}")


def cmd_read_sram(drive, args) -> None:
    """Legge la SRAM a blocchi e salva ogni blocco subito: alcuni indirizzi bloccano il controller."""
    drive.vuc_system_info()
    with open(args.out, "wb") as f:
        for addr in range(args.address, args.address + args.size, args.chunk):
            data = drive.vuc_read_sram(addr, min(args.chunk, args.address + args.size - addr))
            f.write(data)
            f.flush()
            print(f"{addr:#x}: {len(data)} byte, non nulli {sum(1 for c in data if c)}", file=sys.stderr)


def cmd_probe_ce(drive, args) -> None:
    """Legge (blocco, pagina) con un valore grezzo del byte CE nel parametro di READ_FLASH.

    Psychite usa la posizione del bit nella ce_bitmap (0/4/8/12): 4 e 12 rileggono CE0/CE2 con pagina+2.
    Serve a trovare la codifica che seleziona davvero CE1/CE3. Un valore errato può bloccare il controller.
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
    print(f"ce_raw {args.ce_raw}: indice OOB {pidx}, byte8 {oob[8]}, oob {oob[:16].hex()}, sha1 {hashlib.sha1(data).hexdigest()[:12]}")
    if args.out:
        pathlib.Path(args.out).write_bytes(data)
        pathlib.Path(args.out + ".oob").write_bytes(oob)


# Significato dei bit del flag di protect (0x5C0CB5F0), dal disassemblato di SBFM21.1:
#   bit 0 -> FUN_6003bde8: contesto NAND +0xfec diverso da zero
#   bit 1 -> FUN_60056864: stato di un pin/registro hardware (reg+0x31c bit 9), polarita' da config
#   bit 2 -> FUN_60016c4c: la scansione dell'area di sistema ha trovato una pagina "ERROR_UNIT"
#   bit 3 -> letto insieme al bit 2 da FUN_6000892c; il setter non e' nelle funzioni decompilate
PROTECT_BITS = {
    0: "bit0: contesto NAND non valido (FUN_6003bde8)",
    1: "bit1: pin/registro hardware (FUN_60056864)",
    2: "bit2: ERROR_UNIT o pagina cancellata nell'area di sistema (FUN_60016c4c)",
    3: "bit3: condizione sconosciuta, consumata con il bit2 (FUN_6000892c)",
}

# Variabili di diagnosi scritte dalla scansione di init FUN_60016c4c.
# (indirizzo, lunghezza, descrizione). Tutte in IRAM/SRAM: sola lettura, nessuna NAND.
DIAG_VARS = [
    (0x5C0CB5F0, 1, "flag di protect (bitfield)"),
    (0x5C0CEAAC, 1, "blocco in cui la scansione ha visto ERROR_UNIT"),
    (0x5C0CE6DA, 1, "blocco del SYSTEM_UNIT_HEADER trovato (0xff = nessuno)"),
    (0x5C0CE6DB, 1, "blocco del BLOCK_MAP trovato (0xff = nessuno)"),
    (0x5C0CE9AB, 1, "limite di blocchi della scansione (init 100)"),
    (0x5C0CE6B4, 1, "numero di CE"),
    (0x5C0CEAE8, 4, "bitmap dei CE"),
    (0x5C0CA0E0, 2, "contatori: SYSTEM_UNIT_HEADER, BLOCK_MAP"),
    (0x5C0CE6EE, 1, "flag di geometria inizializzata"),
]
DIAG_SRAM = [
    (0x6005CD40, 8, "array blocchi SYSTEM_UNIT_HEADER"),
    (0x6005CD00, 8, "array blocchi BLOCK_MAP"),
    (0x6005CD10, 32, "array numeri di sequenza (u32)"),
    (0x50001200, 0x400, "buffer OOB della scansione (4 slot da 0x100)"),
]

# Magic del primo u32 dell'OOB, come li classifica FUN_60016c4c e il resto del firmware.
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
    """Classifica il primo u32 dell'OOB con le stesse regole del firmware.

    Il test di ERROR_UNIT e' una maschera, non un confronto: (~v & 0xFFD00000) == 0. Percio'
    0xFFFFFFFF (pagina cancellata o lettura non correggibile) ricade nello stesso ramo e fa
    impostare il bit 2 del flag di protect.
    """
    if (~value & ERROR_UNIT_MASK & 0xFFFFFFFF) == 0:
        return "ERROR_UNIT (cancellata)" if value == 0xFFFFFFFF else "ERROR_UNIT"
    if value in PAGE_MAGIC:
        return PAGE_MAGIC[value]
    return f"LBA {value:#x}"


def cmd_diag_protect(drive, args) -> None:
    """Legge le variabili che la scansione di init lascia in RAM. Sola lettura, nessuna scrittura.

    FUN_60016c4c scorre pagina 0 dei blocchi 0..limite su ogni CE, classifica il primo u32 dell'OOB
    e registra cosa ha trovato. Leggere queste variabili dice *perche'* il disco e' in protect mode
    e su quale blocco si e' inceppato, senza bisogno di un loader diagnostico.
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
            print(f"    flag = {data[0]:#04x}: " + ("; ".join(bits + extra) or "nessun bit"))
    if not args.sram:
        return
    for address, size, label in DIAG_SRAM:
        data = drive.vuc_read_sram(address, size)
        print(f"{address:#010x} [{size}] {label}")
        for off in range(0, size, 32):
            print(f"    +{off:#05x} {data[off:off + 32].hex()}")


def cmd_sys_scan(drive, args) -> None:
    """Rilegge pagina 0 dei blocchi di sistema come fa la scansione di init, e la classifica.

    Serve a trovare la pagina che il firmware interpreta come ERROR_UNIT. Sola lettura.
    Il modo di lettura conta: un blocco pSLC letto in modo MLC sembra cancellato, cioe' 0xffffffff,
    che e' esattamente il valore che fa scattare il protect. Per questo va provato in entrambi i modi.
    """
    info = drive.vuc_system_info()
    out = open(args.out, "w") if args.out else None
    for ce in _parse_range(args.ce, info.ce_count):
        for block in _parse_range(args.blocks, info.blocks_per_die):
            try:
                _data, oob = drive.read_page(ce, args.die, block, 0, args.pslc, info)
            except Exception as exc:  # una pagina illeggibile non deve fermare la scansione
                line = f"ce {ce} blocco {block:4d}: errore {exc}"
            else:
                value = struct.unpack_from("<I", oob, 0)[0]
                seq = struct.unpack_from("<I", oob, 4)[0]
                line = (f"ce {ce} blocco {block:4d}: {value:08x} {classify_oob_header(value):<26}"
                        f" seq {seq & 0xFFFFFF:#08x} ecc {oob[8]:#04x} ce_id {oob[10]:#04x}")
            print(line, flush=True)
            if out:
                out.write(line + "\n")
                out.flush()
    if out:
        out.close()


def cmd_product_history(drive, args) -> None:
    """Legge la product history (VUC 0xDA, sola lettura).

    Su questi controller contiene tipicamente i contatori di vita: accensioni, ore, e in particolare
    le perdite di alimentazione inattese. Serve a decidere la causa prima del guasto.
    """
    from phison_s11 import drive as s11_drive

    drive.vuc_system_info()
    data = drive.vuc(s11_drive.VUCFeature.READ_PRODUCT_HISTORY, args.size)
    print(f"{len(data)} byte")
    if args.out:
        pathlib.Path(args.out).write_bytes(data)
    for off in range(0, min(len(data), args.show), 16):
        chunk = data[off:off + 16]
        ascii_ = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"  +{off:04x} {chunk.hex(' ')}  {ascii_}")


def cmd_restart(drive, args) -> None:
    """Soft reset del controller: ricarica le sezioni dalla NAND e rifa la scansione di init.

    Volatile, nessuna scrittura NAND. Serve dopo aver cancellato l'error unit: la sospensione S3
    fa solo un COMRESET, mentre la scansione di `FUN_60016c4c` gira al reset del controller.
    """
    drive.vuc_system_info()
    before = drive.vuc_read_register(0x5C0CB5F0, 1)
    ident0 = drive.cmd_identify_device()
    print(f"prima: flag={before.hex()}, IDENTIFY model={ident0.model!r} firmware={ident0.firmware!r}")
    drive.allow_restart = True
    try:
        drive.vuc_restart()
    except Exception as e:
        raise SystemExit(f"reset: {e!r} (il controller potrebbe essersi bloccato; recupera con S3+rescan)")
    finally:
        drive.allow_restart = False
    for address, size, label in DIAG_VARS:
        data = drive.vuc_read_register(address, size)
        print(f"{address:#010x} [{size}] {data.hex():<8} {label}")
        if address == 0x5C0CB5F0 and size == 1:
            bits = [text for bit, text in PROTECT_BITS.items() if data[0] >> bit & 1]
            print(f"    flag = {data[0]:#04x}: " + ("; ".join(bits) or "NESSUN BIT: protect mode spento"))
    ident = drive.cmd_identify_device()
    print(f"dopo:  IDENTIFY model={ident.model!r} firmware={ident.firmware!r}")


def cmd_erase_block(drive, args) -> None:
    """Cancella un blocco NAND. IRREVERSIBILE. Pensato per l'error unit che tiene il disco in protect.

    Tre interlock prima di scrivere:
      1. la pagina 0 del blocco deve avere il magic atteso (default: la maschera ERROR_UNIT), letta
         con lo stesso indirizzamento che usera' l'erase, quindi e' davvero quel blocco;
      2. deve esistere un backup locale completo del blocco (dati + OOB), passato con --backup;
      3. serve --yes.
    Dopo l'erase rilegge la pagina 0 e stampa com'e' rimasta.
    """
    info = drive.vuc_system_info()
    data, oob = drive.read_page(args.ce, args.die, args.block, 0, args.pslc, info)
    value = struct.unpack_from("<I", oob, 0)[0]
    kind = classify_oob_header(value)
    print(f"ce {args.ce} die {args.die} blocco {args.block}: pagina 0 word0 = {value:#010x} ({kind})")
    scritte = sum(1 for p in range(len(oob) // 512) if oob[p * 512 + 8] != 0xFF)
    print(f"  pagine con dati in questa lettura della pagina 0: OOB byte8 = {oob[8]:#04x}")

    if args.expect == "error-unit":
        if (~value & ERROR_UNIT_MASK & 0xFFFFFFFF) != 0:
            raise SystemExit(f"INTERLOCK 1: la pagina 0 non e' un ERROR_UNIT ({value:#010x}), nessun erase")
    elif args.expect != "qualsiasi":
        if value != int(args.expect, 0):
            raise SystemExit(f"INTERLOCK 1: word0 {value:#010x} != {args.expect}, nessun erase")

    backup = pathlib.Path(args.backup)
    bo = backup.with_suffix(".oob")
    if not (backup.exists() and bo.exists()):
        raise SystemExit(f"INTERLOCK 2: backup mancante ({backup} / {bo}), nessun erase")
    saved = bo.read_bytes()
    if struct.unpack_from("<I", saved, 0)[0] != value:
        raise SystemExit("INTERLOCK 2: il backup non corrisponde a questo blocco, nessun erase")
    print(f"  backup: {backup} ({backup.stat().st_size} B) + OOB ({len(saved)} B), word0 coincide")

    if not args.yes:
        raise SystemExit("manca --yes: nessun erase eseguito")

    drive.allow_erase = True
    try:
        drive.vuc_erase_flash(args.ce, args.die, args.block, args.pslc, info)
    finally:
        drive.allow_erase = False
    print("  ERASE eseguito")

    _data, oob2 = drive.read_page(args.ce, args.die, args.block, 0, args.pslc, info)
    v2 = struct.unpack_from("<I", oob2, 0)[0]
    print(f"  dopo: word0 = {v2:#010x} ({classify_oob_header(v2)}), OOB byte8 = {oob2[8]:#04x}")
    print(f"  OOB pagina 0: {oob2[:16].hex()}")


def cmd_clear_protect(drive, args) -> None:
    """Azzera in RAM il flag di protect mode (0x5C0CB5F0). Scrittura volatile nel controller, nessuna NAND.

    Test diagnostico: se dopo IDENTIFY riporta il modello normale e `dd if=/dev/sdX` legge dati reali,
    la FTL era gia' montata; se legge zeri, serve ri-eseguire il boot.
    """
    PROTECT_FLAG_ADDR = 0x5C0CB5F0
    drive.vuc_system_info()
    before = drive.cmd_identify_device()
    cur = drive.vuc_read_register(PROTECT_FLAG_ADDR, 1)
    print(f"prima: IDENTIFY model={before.model!r} firmware={before.firmware!r}; flag={cur.hex()}")
    if not args.yes:
        raise SystemExit("manca --yes: nessuna scrittura eseguita")
    drive.allow_write_register = True
    drive.vuc_write_register(PROTECT_FLAG_ADDR, b"\x00")
    drive.allow_write_register = False
    now = drive.vuc_read_register(PROTECT_FLAG_ADDR, 1)
    after = drive.cmd_identify_device()
    print(f"dopo:  IDENTIFY model={after.model!r} firmware={after.firmware!r}; flag={now.hex()}")


def cmd_probe_reset_patch(drive, args) -> None:
    """Patcha in RAM l'istruzione che imposta il protect (0x60017003) e verifica se sopravvive a un reset.

    Originale: s8i a9,a10,0 (92 4a 00) scrive flag|4. Patch: or a9,a9,a9 (90 99 20) = no-op.
    Scrittura volatile nella SRAM del controller, nessuna NAND. Con --restart fa un soft reset e
    rilegge: se i byte restano patchati la RAM sopravvive al reset (via in-place praticabile); se
    tornano originali il reset ricarica dalla NAND (serve ROM mode).
    """
    ADDR = 0x60017003
    ORIG = bytes.fromhex("924a00")
    PATCH = bytes.fromhex("909920")
    FLAG = 0x5C0CB5F0
    drive.vuc_system_info()
    cur = drive.vuc_read_register(ADDR, 3)
    print(f"istruzione a {ADDR:#x}: {cur.hex()} ({'originale' if cur == ORIG else 'gia patchata' if cur == PATCH else 'ALTRO'})")
    if cur not in (ORIG, PATCH):
        raise SystemExit("i byte non corrispondono a quelli attesi: non tocco niente")
    if not args.yes:
        raise SystemExit("manca --yes: nessuna scrittura eseguita")
    drive.allow_write_register = True
    # WRITE_REGISTER scrive parole da 4 byte allineate: patch via read-modify-write sulle due parole coinvolte
    base = ADDR & ~3  # 0x60017000
    span = bytearray(drive.vuc_read_register(base, 8))  # copre 0x60017000..0x60017007
    off = ADDR - base  # 3
    span[off : off + 3] = PATCH
    drive.vuc_write_register(base, bytes(span[0:4]))
    drive.vuc_write_register(base + 4, bytes(span[4:8]))
    back = drive.vuc_read_register(ADDR, 3)
    print(f"dopo patch: {back.hex()} ({'ok' if back == PATCH else 'SCRITTURA FALLITA'})")
    drive.allow_write_register = False
    if back != PATCH:
        raise SystemExit("la scrittura in SRAM non ha attecchito: WRITE_REGISTER non raggiunge questa zona")
    if not args.restart:
        print("patch applicata in RAM; senza --restart non resetto")
        return
    print("eseguo soft reset...")
    drive.allow_restart = True
    try:
        drive.vuc_restart()
    except Exception as e:
        drive.allow_restart = False
        raise SystemExit(f"reset: {e!r} (il controller potrebbe essersi bloccato; recupera con S3+rescan)")
    drive.allow_restart = False
    after = drive.vuc_read_register(ADDR, 3)
    flag = drive.vuc_read_register(FLAG, 1)
    ident = drive.cmd_identify_device()
    sopravv = after == PATCH
    print(f"dopo reset: istruzione {after.hex()} -> RAM {'SOPRAVVISSUTA' if sopravv else 'ricaricata da NAND'}")
    print(f"            flag protect={flag.hex()}, IDENTIFY model={ident.model!r} firmware={ident.firmware!r}")


def cmd_read_firmware(drive, args) -> None:
    """Estrae il firmware installato (example/read_firmware.py di Psychite): SEND_SEED + VERIFY_FLASH."""
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
        # dati grezzi, prima di qualunque interpretazione: header di flash + sezioni come restituite dal disco
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
            print(f"sezione {i}: {section} -> {len(data)} byte")
        return
    firmware = module.read_firmware(drive)
    data = bytes(firmware)
    pathlib.Path(args.out).write_bytes(data)
    print(f"firmware: {firmware}")
    print(f"salvato {args.out}: {len(data)} byte")


def cmd_update_firmware(drive, args) -> None:
    """DOWNLOAD MICROCODE segmentato di un solo file, verificato per SHA-256 e con Psychite. Scrive sul disco."""
    import hashlib

    from phison_s11 import firmware as s11_firmware

    data = pathlib.Path(args.firmware).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.sha256:
        raise SystemExit(f"SHA-256 {digest} diverso da quello atteso")
    firmware = s11_firmware.Firmware.from_bytes(data)  # verifica struttura e CRC delle sezioni
    info = drive.vuc_system_info()
    print(f"prima: {drive.cmd_identify_device().firmware}, protected_mode {info.protected_mode}")
    print(f"carico: {firmware.version} {firmware.date}")
    if not args.yes:
        raise SystemExit("manca --yes: nessuna scrittura eseguita")
    drive.allow_dlmc_data = data
    drive.cmd_download_microcode_segmented(data)
    drive.allow_dlmc_data = None
    print(f"dopo: IDENTIFY firmware {drive.cmd_identify_device().firmware}")


def cmd_engineering(drive, args) -> None:
    """DOWNLOAD MICROCODE modo 7 con il solo header engineering (Psychite: cambia modalità, non scrive firmware)."""
    from phison_s11 import firmware as s11_firmware

    before = drive.vuc_system_info()
    print(f"prima: vuc_mode {before.vuc_mode}, protected_mode {before.protected_mode}")
    if not args.yes:
        raise SystemExit("manca --yes: nessun comando inviato")
    drive.allow_engineering_dlmc = True
    drive.cmd_download_microcode_full(bytes(s11_firmware.Header(engineering_mode=True)))
    drive.allow_engineering_dlmc = False
    after = drive.vuc_system_info()
    print(f"dopo: vuc_mode {after.vuc_mode}, protected_mode {after.protected_mode}, IDENTIFY {drive.cmd_identify_device().firmware}")


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
    print(f"dati {len(data)} B, OOB: {oob[:32].hex()}")


def cmd_dump(drive, args) -> None:
    info = drive.vuc_system_info()
    # piano (file o -): "skip ce die block", "skippage ce die block page", "only ce die block"
    skip: set[tuple[int, int, int]] = set()
    skip_pages: set[tuple[int, int, int, int]] = set()
    only: list[tuple[int, int, int]] = []
    if args.plan:
        src = sys.stdin if args.plan == "-" else open(args.plan)
        for line in src:
            kind, *nums = line.split() or [""]
            if kind == "skip":
                skip.add(tuple(map(int, nums)))
            elif kind == "skippage":
                skip_pages.add(tuple(map(int, nums)))
            elif kind == "only":
                only.append(tuple(map(int, nums)))
            elif kind:
                raise SystemExit(f"riga di piano non valida: {line!r}")
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
                data, oob, status = b"saltata: aveva bloccato il controller", b"", STATUS_SKIPPED
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
                    # solo l'errore ATA (es. ECC non correggibile) è tollerato; timeout, ABORTED_COMMAND
                    # o errori SG_IO vogliono dire controller bloccato: ogni altro comando peggiora le cose
                    fatal = "ATA command failed" not in str(e)
            out.write(PAGE_HEADER.pack(MAGIC_PAGE, ce, die, block, page, flags, status, len(data), len(oob)))
            out.write(data)
            out.write(oob)
            n_pages += 1
            if fatal or consecutive_errors >= args.max_errors:
                out.flush()
                # riga per dump_runner.py
                print(f"FATAL {ce} {die} {block} {page}", file=sys.stderr)
                raise SystemExit(f"mi fermo a ce {ce} die {die} blocco {block} pagina {page}: {data.decode()}")
        out.write(BLOCK_DONE.pack(MAGIC_BLOCK, ce, die, block))
        out.flush()
        rate = n_pages / max(time.monotonic() - t0, 1e-6)
        print(f"blocco ce {ce} die {die} {block} ok, {rate:.1f} pagine/s", file=sys.stderr)
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
    """Riceve lo stream di dump: un file .data/.oob per blocco, errori in .err, blocchi completi in manifest."""
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
            print("stream interrotto (blocco in corso scartato)", file=sys.stderr)
            break
        if magic == MAGIC_END:
            print("fine stream", file=sys.stderr)
            break
        if magic == MAGIC_PAGE:
            _, ce, die, block, page, flags, status, dlen, olen = PAGE_HEADER.unpack(
                magic + _read_exact(stream, PAGE_HEADER.size - 4)
            )
            data = _read_exact(stream, dlen)
            oob = _read_exact(stream, olen)
            _, fdata, foob, ferr = files(ce, die, block)
            if status == STATUS_OK:  # errori e pagine saltate restano a zero e finiscono in .err
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
            raise SystemExit(f"stream corrotto: magic {magic!r}")


def cmd_done_list(args) -> None:
    path = pathlib.Path(args.outdir) / "manifest.txt"
    if path.exists():
        sys.stdout.write(path.read_text())


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("drive", help="dispositivo /dev/sgX (ignorato da receive/done-list: usare -)")
    p.add_argument("--log", default="safe_s11.log", help="log JSONL di ogni comando ATA")
    p.add_argument("--log-errors-only", action="store_true", help="registra solo errori e comandi bloccati")
    sub = p.add_subparsers(dest="action", required=True)

    sub.add_parser("identify")
    s = sub.add_parser("sysinfo")
    s.add_argument("--raw")
    s = sub.add_parser("info-block")
    s.add_argument("--raw")
    sub.add_parser("flash-id")
    s = sub.add_parser("block-map")
    s.add_argument("--out")
    s = sub.add_parser("unlock", help="sequenza di unlock VUC (scrive registri di stato del controller)")
    s.add_argument("--allow-engineering-dlmc", action="store_true", help="ammette DLMC con il solo header engineering")
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
    s = sub.add_parser("diag-protect", help="legge le variabili di diagnosi della scansione di init (sola lettura)")
    s.add_argument("--sram", action="store_true", help="legge anche gli array e il buffer OOB in SRAM")
    s = sub.add_parser("sys-scan", help="riclassifica pagina 0 dei blocchi di sistema come fa l'init (sola lettura)")
    s.add_argument("--ce", default="all")
    s.add_argument("--die", type=int, default=0)
    s.add_argument("--blocks", default="0-99")
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--out")
    s = sub.add_parser("product-history", help="legge la product history del controller (sola lettura)")
    s.add_argument("--size", type=lambda x: int(x, 0), default=512)
    s.add_argument("--show", type=lambda x: int(x, 0), default=256)
    s.add_argument("--out")
    sub.add_parser("restart", help="soft reset del controller: ricarica dalla NAND e rifa l'init (volatile)")
    s = sub.add_parser("erase-block", help="CANCELLA un blocco NAND (irreversibile); pensato per l'error unit")
    s.add_argument("--ce", type=int, required=True)
    s.add_argument("--die", type=int, default=0)
    s.add_argument("--block", type=int, required=True)
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--expect", default="error-unit",
                   help="magic atteso nella pagina 0: 'error-unit' (default), 'qualsiasi', o un valore tipo 0xffd00000")
    s.add_argument("--backup", required=True, help="file .data del backup locale del blocco (serve anche il .oob)")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("clear-protect", help="azzera in RAM il flag di protect (scrittura volatile nel controller)")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("probe-reset-patch", help="patcha in RAM la set-protect e testa se sopravvive a un reset")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--restart", action="store_true", help="dopo la patch esegue un soft reset e rilegge")
    s = sub.add_parser("read-firmware", help="estrae il firmware installato (abilita SEND_SEED e VERIFY_FLASH)")
    s.add_argument("--out", required=True)
    s.add_argument("--psychite-example", default="/run/live/medium/live/psychite/example")
    s.add_argument("--raw", action="store_true", help="salva header e sezioni grezzi senza interpretarli")
    s = sub.add_parser("update-firmware", help="DOWNLOAD MICROCODE segmentato (SCRIVE sul disco)")
    s.add_argument("firmware")
    s.add_argument("--sha256", required=True)
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("engineering", help="header engineering via DOWNLOAD MICROCODE (nessun firmware scritto)")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("read-page")
    for name in ("ce", "die", "block", "page"):
        s.add_argument(name, type=int)
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--out")
    s = sub.add_parser("dump")
    s.add_argument("--ce", default="all")
    s.add_argument("--die", default="all")
    s.add_argument("--blocks", default="all", help="es. 0-99,200")
    s.add_argument("--pages", default="all", help="es. 0 oppure 0-1023")
    s.add_argument("--pslc", action="store_true")
    s.add_argument("--plan", help="file (o -) con righe 'skip|only ce die block' e 'skippage ce die block page'")
    s.add_argument("--max-errors", type=int, default=3, help="errori ATA (ECC) consecutivi prima di fermarsi")
    s.add_argument("--out", required=True, help="file o - per stdout")
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
        raise SystemExit(f"BLOCCATO: {e}")
    finally:
        drive.close()


if __name__ == "__main__":
    main()
