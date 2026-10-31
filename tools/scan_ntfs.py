#!/usr/bin/env python3
"""Counts NTFS MFT records and directory indexes in raw dumps.

A valid MFT record: a "FILE" signature at 1024-byte alignment, allocated size (+0x1c) of 1024 or
4096, flags (+0x16) in 0..3 and a plausible update-sequence offset (+0x04). Without those checks
the signature alone produces false positives inside user data -- which is how a drive can look
like it has lost its MFT when it has not.

Usage:
  scan_ntfs.py DUMPDIR [DUMPDIR...]
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
            found["valid MFT"] += 1
            found[f"  flags={flags}"] += 1
        else:
            found["invalid FILE"] += 1


def main():
    found = collections.Counter()
    nfiles = 0
    for d in sys.argv[1:]:
        for path in sorted(pathlib.Path(d).rglob("*.data")):
            scan_file(path, found)
            nfiles += 1
            if nfiles % 500 == 0:
                print(f"{nfiles} files, {dict(found)}", flush=True)
    print(f"TOTAL {nfiles} files: {dict(found)}", flush=True)


if __name__ == "__main__":
    main()
