#!/usr/bin/env python3
"""Rebuilds a disk image from the raw dump using the LBA tags written in the OOB.

Observed OOB format (user pages, 16 KB = 4 frames of 4 KB):
  entry 0 (bytes 0-15):  page header: u32 LBA of the first frame, u32 superblock sequence,
                         byte 8 = corrected bits (0xFF = page never written)
  entries 1-4:           one frame each: u32 LBA in sectors (0x1FFFFFE8 = empty frame), ..., CRC
Several versions of the same LBA: the key (superblock sequence, page, block order) wins.
That rule is unverified, which is why `index` prints duplicate statistics before writing anything.

Usage:
  rebuild_image.py index DUMPDIR [DUMPDIR...] --out index.bin
  rebuild_image.py image index.bin --out disk.img
"""

import argparse
import array
import collections
import pathlib
import struct
import sys

# TODO: hard-coded for the drive this was written against. It should come from the dump
# (the controller's SystemInfo is already read by safe_dump.py) or from a command-line option.
SECTORS = 234441648  # IDENTIFY / info block
FRAME = 4096
PAGE = 16384
OOB = 512
EMPTY_LBA = 0x1FFFFFE8
UNITS = SECTORS // 8  # 4 KB units


def blocks(dumpdirs):
    """(id, base path) of the complete blocks, in a stable order."""
    out = []
    for d in dumpdirs:
        d = pathlib.Path(d)
        for line in (d / "manifest.txt").read_text().splitlines():
            if len(line.split()) != 3:  # a short line means the dump is still running
                continue
            ce, die, block = map(int, line.split())
            out.append((ce, die, block, d / f"ce{ce}" / f"die{die}" / f"b{block:05d}"))
    return out


def cmd_index(args) -> None:
    blist = blocks(args.dumpdirs)
    if len(blist) >= 1 << 16:
        raise SystemExit("too many blocks for the index")
    best_key = array.array("Q", bytes(8 * UNITS))  # 0 = no version
    best_loc = array.array("Q", bytes(8 * UNITS))
    versions = array.array("B", bytes(UNITS))
    stats = collections.Counter()
    seqs = collections.Counter()
    for bid, (ce, die, block, base) in enumerate(blist):
        oob = (base.with_suffix(".oob")).read_bytes()
        for page in range(len(oob) // OOB):
            o = oob[page * OOB : (page + 1) * OOB]
            if o[8] == 0xFF:
                stats["pages never written"] += 1
                continue
            seq = struct.unpack_from("<I", o, 4)[0]
            if o[4:8].hex().endswith("2211ff") or (seq >> 24) != 0xFF:
                stats["non-user pages"] += 1
                continue
            seqs[seq] += 1
            # physical page index from the OOB (bytes 14-15 / 0x40): on odd CEs the position
            # within the file is offset by 2
            pidx = int.from_bytes(o[14:16], "big") // 0x40
            # key: sequence (low 24 bits), physical page, block order within the superblock (ce, block)
            # TODO: this ordering picks the correct version only 42% of the time among complete
            # frames, measured against the repaired drive. The right key is not known; see the
            # open problems in the README. Everything downstream inherits that error rate.
            key = ((seq & 0xFFFFFF) << 32) | (pidx << 16) | (block << 2) | ce
            for frame in range(4):
                lba = struct.unpack_from("<I", o, 16 * (frame + 1))[0]
                if lba == EMPTY_LBA:
                    stats["empty frames"] += 1
                    continue
                if lba % 8 or lba >= SECTORS:
                    stats["frames with an odd LBA"] += 1
                    continue
                unit = lba // 8
                stats["frames mapped"] += 1
                if versions[unit] < 255:
                    versions[unit] += 1
                if key > best_key[unit]:
                    best_key[unit] = key
                    best_loc[unit] = (bid << 32) | (page << 8) | frame
        if bid % 200 == 0:
            print(f"{bid}/{len(blist)} blocks", file=sys.stderr)
    multi = collections.Counter(min(v, 5) for v in versions if v)
    print("statistics:", dict(stats))
    print("4 KB units with data:", sum(1 for k in best_key if k), "of", UNITS)
    print("versions per unit (5 = 5+):", dict(sorted(multi.items())))
    print("distinct superblock sequences:", len(seqs))
    with open(args.out, "wb") as f:
        f.write(struct.pack("<I", len(blist)))
        for ce, die, block, base in blist:
            name = str(base).encode()
            f.write(struct.pack("<H", len(name)) + name)
        best_loc.tofile(f)
        best_key.tofile(f)


def cmd_image(args) -> None:
    with open(args.index, "rb") as f:
        n = struct.unpack("<I", f.read(4))[0]
        names = []
        for _ in range(n):
            ln = struct.unpack("<H", f.read(2))[0]
            names.append(f.read(ln).decode())
        best_loc = array.array("Q")
        best_loc.fromfile(f, UNITS)
        best_key = array.array("Q")
        best_key.fromfile(f, UNITS)
    files: dict[int, object] = {}
    written = 0
    with open(args.out, "wb") as img:
        img.truncate(SECTORS * 512)  # sparse: anything never written stays zero
        for unit in range(UNITS):
            if not best_key[unit]:
                continue
            loc = best_loc[unit]
            bid, page, frame = loc >> 32, (loc >> 8) & 0xFFFFFF, loc & 0xFF
            if bid not in files:
                if len(files) > 64:
                    for fh in files.values():
                        fh.close()
                    files.clear()
                files[bid] = open(names[bid] + ".data", "rb")
            src = files[bid]
            src.seek(page * PAGE + frame * FRAME)
            img.seek(unit * FRAME)
            # TODO: this writes the whole 4 KB frame at the unit's offset, which is wrong for a
            # partial frame -- it holds a contiguous tail of the unit at offset 0, with 0x78 fill
            # after it. The rule was worked out after this tool was written and is documented in
            # docs/02-page-format.md; applying it here (shift = 8 - run length of OOB byte 9, and
            # leave the rest of the unit untouched) is the main thing missing.
            img.write(src.read(FRAME))
            written += 1
            if written % 500000 == 0:
                print(f"{written} units written", file=sys.stderr)
    print(f"image {args.out}: {written} 4 KB units written")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("index")
    s.add_argument("dumpdirs", nargs="+")
    s.add_argument("--out", required=True)
    s = sub.add_parser("image")
    s.add_argument("index")
    s.add_argument("--out", required=True)
    args = p.parse_args()
    {"index": cmd_index, "image": cmd_image}[args.action](args)


if __name__ == "__main__":
    main()
