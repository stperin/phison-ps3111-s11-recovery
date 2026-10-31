#!/usr/bin/env python3
"""Ricostruisce un'immagine del disco dal dump raw usando gli LBA scritti negli OOB.

Formato OOB osservato (pagine utente, 16 KB = 4 frame da 4 KB):
  voce 0 (byte 0-15):  intestazione pagina: u32 LBA primo frame, u32 sequenza superblocco, byte 8 = bit corretti
                       (0xFF = pagina cancellata)
  voci 1-4:            un frame ciascuna: u32 LBA in settori (0x1FFFFFE8 = frame vuoto), ..., CRC
Più versioni dello stesso LBA: vince la chiave (sequenza superblocco, pagina, ordine del blocco).
La regola va verificata: per questo `index` stampa statistiche sui duplicati prima di scrivere.

Uso:
  rebuild_image.py index DUMPDIR [DUMPDIR...] --out index.bin
  rebuild_image.py image index.bin --out disco.img
"""

import argparse
import array
import collections
import pathlib
import struct
import sys

SECTORS = 234441648  # IDENTIFY / info block
FRAME = 4096
PAGE = 16384
OOB = 512
EMPTY_LBA = 0x1FFFFFE8
UNITS = SECTORS // 8  # unità da 4 KB


def blocks(dumpdirs):
    """(id, path base) dei blocchi completi, in ordine stabile."""
    out = []
    for d in dumpdirs:
        d = pathlib.Path(d)
        for line in (d / "manifest.txt").read_text().splitlines():
            if len(line.split()) != 3:  # riga incompleta se il dump è ancora in corso
                continue
            ce, die, block = map(int, line.split())
            out.append((ce, die, block, d / f"ce{ce}" / f"die{die}" / f"b{block:05d}"))
    return out


def cmd_index(args) -> None:
    blist = blocks(args.dumpdirs)
    if len(blist) >= 1 << 16:
        raise SystemExit("troppi blocchi per l'indice")
    best_key = array.array("Q", bytes(8 * UNITS))  # 0 = nessuna versione
    best_loc = array.array("Q", bytes(8 * UNITS))
    versions = array.array("B", bytes(UNITS))
    stats = collections.Counter()
    seqs = collections.Counter()
    for bid, (ce, die, block, base) in enumerate(blist):
        oob = (base.with_suffix(".oob")).read_bytes()
        for page in range(len(oob) // OOB):
            o = oob[page * OOB : (page + 1) * OOB]
            if o[8] == 0xFF:
                stats["pagine cancellate"] += 1
                continue
            seq = struct.unpack_from("<I", o, 4)[0]
            if o[4:8].hex().endswith("2211ff") or (seq >> 24) != 0xFF:
                stats["pagine non utente"] += 1
                continue
            seqs[seq] += 1
            # indice di pagina fisico dall'OOB (byte 14-15 / 0x40): sui CE dispari la posizione nel file è sfasata di 2
            pidx = int.from_bytes(o[14:16], "big") // 0x40
            # chiave: sequenza (24 bit bassi), pagina fisica, ordine del blocco nel superblocco (ce, blocco)
            key = ((seq & 0xFFFFFF) << 32) | (pidx << 16) | (block << 2) | ce
            for frame in range(4):
                lba = struct.unpack_from("<I", o, 16 * (frame + 1))[0]
                if lba == EMPTY_LBA:
                    stats["frame vuoti"] += 1
                    continue
                if lba % 8 or lba >= SECTORS:
                    stats["frame con LBA anomalo"] += 1
                    continue
                unit = lba // 8
                stats["frame mappati"] += 1
                if versions[unit] < 255:
                    versions[unit] += 1
                if key > best_key[unit]:
                    best_key[unit] = key
                    best_loc[unit] = (bid << 32) | (page << 8) | frame
        if bid % 200 == 0:
            print(f"{bid}/{len(blist)} blocchi", file=sys.stderr)
    multi = collections.Counter(min(v, 5) for v in versions if v)
    print("statistiche:", dict(stats))
    print("unità da 4 KB con dati:", sum(1 for k in best_key if k), "su", UNITS)
    print("versioni per unità (5 = 5+):", dict(sorted(multi.items())))
    print("sequenze superblocco distinte:", len(seqs))
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
        img.truncate(SECTORS * 512)  # sparso: le parti mai scritte restano a zero
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
            img.write(src.read(FRAME))
            written += 1
            if written % 500000 == 0:
                print(f"{written} unità scritte", file=sys.stderr)
    print(f"immagine {args.out}: {written} unità da 4 KB scritte")


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
