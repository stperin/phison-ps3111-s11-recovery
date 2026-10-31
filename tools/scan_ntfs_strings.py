#!/usr/bin/env python3
"""Searches the dumps for NTFS structural signatures, independent of MFT record layout.

The cross-check for the "FILE" record count: if the MFT really were gone, the metafile names
would have to be missing too -- in NTFS they are stored as UTF-16LE.

Usage:
  scan_ntfs_strings.py DUMPDIR [DUMPDIR...]
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
    examples = collections.defaultdict(set)
    n = 0
    for d in sys.argv[1:]:
        for path in sorted(pathlib.Path(d).rglob("*.data")):
            data = path.read_bytes()
            for name, needle in NEEDLES.items():
                off = data.find(needle)
                while off >= 0:
                    found[name] += 1
                    if len(examples[name]) < 8:
                        examples[name].add(path.name)
                    off = data.find(needle, off + 1)
            n += 1
            if n % 1000 == 0:
                print(f"{n} files: {dict(found)}", flush=True)
    print(f"TOTAL {n} files", flush=True)
    for name in NEEDLES:
        print(f"  {name:18s} {found[name]:8d}  e.g. {sorted(examples[name])[:4]}", flush=True)


if __name__ == "__main__":
    main()
