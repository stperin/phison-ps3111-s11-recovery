#!/usr/bin/env python3
"""Cerca nei dump le firme strutturali di NTFS, indipendenti dal formato dei record MFT.

Serve come controprova al conteggio dei record "FILE": se la MFT e' davvero assente devono
mancare anche i nomi dei metafile, che in NTFS stanno in UTF-16LE.
"""
import collections
import pathlib
import sys

NEEDLES = {
    "boot NTFS": b"NTFS    ",
    "$MFT": "$MFT".encode("utf-16-le"),
    "$MFTMirr": "$MFTMirr".encode("utf-16-le"),
    "$LogFile": "$LogFile".encode("utf-16-le"),
    "$Bitmap": "$Bitmap".encode("utf-16-le"),
    "$BadClus": "$BadClus".encode("utf-16-le"),
    "$Secure": "$Secure".encode("utf-16-le"),
    "INDEX_ROOT $I30": "$I30".encode("utf-16-le"),
    "BOOTMGR": b"BOOTMGR",
    "bootmgfw": "bootmgfw".encode("utf-16-le"),
}


def main():
    found = collections.Counter()
    blocchi = collections.defaultdict(set)
    n = 0
    for d in sys.argv[1:]:
        for path in sorted(pathlib.Path(d).rglob("*.data")):
            data = path.read_bytes()
            for name, needle in NEEDLES.items():
                off = data.find(needle)
                while off >= 0:
                    found[name] += 1
                    if len(blocchi[name]) < 8:
                        blocchi[name].add(path.name)
                    off = data.find(needle, off + 1)
            n += 1
            if n % 1000 == 0:
                print(f"{n} file: {dict(found)}", flush=True)
    print(f"TOTALE {n} file", flush=True)
    for name in NEEDLES:
        print(f"  {name:18s} {found[name]:8d}  es. {sorted(blocchi[name])[:4]}", flush=True)


if __name__ == "__main__":
    main()
