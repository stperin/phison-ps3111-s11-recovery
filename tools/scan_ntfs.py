#!/usr/bin/env python3
"""Conta i record MFT e gli indici di directory NTFS nei dump raw.

Un record MFT valido: firma "FILE" allineata a 1024 byte, dimensione allocata (+0x1c) 1024 o 4096,
flag (+0x16) in 0..3 e offset dell'update sequence (+0x04) plausibile. Senza questi controlli la
firma da sola produce falsi positivi dentro i dati utente.
"""
import collections
import pathlib
import struct
import sys

ALIGN = 1024


def scan_file(path, found):
    data = path.read_bytes()
    for off in range(0, len(data) - 64, ALIGN):
        sig = data[off:off + 4]
        if sig == b"INDX":
            found["INDX"] += 1
            continue
        if sig != b"FILE":
            continue
        usa_off, usa_cnt = struct.unpack_from("<HH", data, off + 4)
        flags = struct.unpack_from("<H", data, off + 0x16)[0]
        used, alloc = struct.unpack_from("<II", data, off + 0x18)
        if alloc in (1024, 4096) and flags < 4 and 0x28 <= usa_off <= 0x40 and used <= alloc:
            found["MFT valido"] += 1
            found[f"  flags={flags}"] += 1
        else:
            found["FILE non valido"] += 1


def main():
    found = collections.Counter()
    nfiles = 0
    for d in sys.argv[1:]:
        for path in sorted(pathlib.Path(d).rglob("*.data")):
            scan_file(path, found)
            nfiles += 1
            if nfiles % 500 == 0:
                print(f"{nfiles} file, {dict(found)}", flush=True)
    print(f"TOTALE {nfiles} file: {dict(found)}", flush=True)


if __name__ == "__main__":
    main()
