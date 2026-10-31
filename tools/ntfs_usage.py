#!/usr/bin/env python3
"""Calcola lo spazio occupato di un volume NTFS dentro un'immagine disco, senza montarla.

Legge il boot sector, poi il record MFT 6 ($Bitmap), ne segue i data run e conta i bit a 1:
un bit per cluster, 1 = cluster in uso.
"""
import struct
import sys


def fixup(rec, bps):
    """Applica l'update sequence: NTFS sostituisce gli ultimi 2 byte di ogni settore."""
    off, cnt = struct.unpack_from("<HH", rec, 4)
    usa = rec[off:off + 2 * cnt]
    rec = bytearray(rec)
    for i in range(1, cnt):
        pos = i * bps - 2
        rec[pos:pos + 2] = usa[2 * i:2 * i + 2]
    return bytes(rec)


def runs(data):
    """Decodifica i data run: lista di (lcn, lunghezza in cluster)."""
    out, i, lcn = [], 0, 0
    while i < len(data) and data[i]:
        ln, lo = data[i] & 0xF, data[i] >> 4
        i += 1
        length = int.from_bytes(data[i:i + ln], "little"); i += ln
        off = int.from_bytes(data[i:i + lo], "little", signed=True); i += lo
        lcn += off
        out.append((lcn, length))
    return out


def main(path, part_sector):
    f = open(path, "rb")
    base = part_sector * 512
    f.seek(base); boot = f.read(512)
    assert boot[3:11] == b"NTFS    ", f"non e' NTFS: {boot[3:11]!r}"
    bps = struct.unpack_from("<H", boot, 0x0B)[0]
    spc = boot[0x0D]
    total_sectors = struct.unpack_from("<Q", boot, 0x28)[0]
    mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
    cps = struct.unpack_from("<b", boot, 0x40)[0]
    recsize = cps * spc * bps if cps > 0 else 1 << -cps
    cluster = bps * spc
    total_clusters = total_sectors // spc
    print(f"settore {bps} B, cluster {cluster} B, record MFT {recsize} B")
    print(f"volume: {total_sectors} settori = {total_sectors*bps/1e9:.1f} GB, {total_clusters} cluster")
    print(f"MFT al cluster {mft_lcn} (LBA assoluto {part_sector + mft_lcn*spc})")

    f.seek(base + mft_lcn * cluster + 6 * recsize)
    rec = fixup(f.read(recsize), bps)
    assert rec[:4] == b"FILE", "record 6 non valido"
    off = struct.unpack_from("<H", rec, 0x14)[0]
    while off < len(rec):
        atype, alen = struct.unpack_from("<II", rec, off)
        if atype == 0xFFFFFFFF:
            break
        if atype == 0x80:  # $DATA
            nonres = rec[off + 8]
            assert nonres, "$Bitmap residente: volume troppo piccolo"
            rstart = struct.unpack_from("<H", rec, off + 0x20)[0]
            rl = runs(rec[off + rstart:off + alen])
            used = 0
            for lcn, length in rl:
                f.seek(base + lcn * cluster)
                for _ in range(length):
                    used += bin(int.from_bytes(f.read(cluster), "little")).count("1")
            used = min(used, total_clusters)
            print(f"\ncluster in uso : {used:10d}  {used*cluster/1e9:7.1f} GB")
            print(f"cluster liberi : {total_clusters-used:10d}  {(total_clusters-used)*cluster/1e9:7.1f} GB")
            print(f"occupazione    : {100*used/total_clusters:.1f}%")
            return
        off += alen
    raise SystemExit("attributo $DATA non trovato in $Bitmap")


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
