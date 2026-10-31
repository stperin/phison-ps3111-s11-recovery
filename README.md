# Phison PS3111-S11: diagnosing and repairing "SATAFIRM S11"

> **TL;DR** — A PS3111-S11 reporting `SATAFIRM S11` is not necessarily bricked, and
> reflashing it is not the first thing to try. On this drive the entire fault was **one
> bit in a RAM flag**, set at every boot because the firmware's system-area scan found a
> single `ERROR_UNIT` page on the NAND. **Erasing that one block ended it permanently.**
> The drive came back as `SPCC M.2 SSD` / `SBFM21.1`, with every byte of user data
> intact; a full image taken from it boots Windows to the desktop. No firmware flash, no
> MPTool, no reinitialisation — each of which would have destroyed the data for good.
> Two read-only commands tell you whether your drive is this case: see
> [Quick check](#quick-check-is-this-your-drive).
>
> This is work I did for myself, on my own drive, and it worked — I got the data back.
> It is not a polished product and it does not pretend to be: one drive, one fault, with
> the dead ends left in. I am publishing it because the findings should be out there
> rather than sitting in my notes, and because someone facing a different Phison problem
> deserves somewhere to start. Take whatever is useful.

Notes and tools from recovering a Silicon Power M56 120 GB SSD (Phison PS3111-S11
controller) that presented itself as `SATAFIRM S11` / firmware `SBFM21W1` and served
no data.

The drive was repaired. It now identifies correctly as `SPCC M.2 SSD` / `SBFM21.1`,
mounts its filesystems, and a full image taken from it boots Windows to the desktop.
The repair was a two-block NAND erase, decided from static analysis of the firmware
rather than by trial and error.

**This is a single case study, not a general tool.** It solved one fault class on one
controller. See [What did not work](docs/04-what-did-not-work.md) for the equally
important half.

---

## Quick check: is this your drive?

Both commands are read-only and take seconds. The second needs
[Psychite](https://github.com/trulycrisp/psychite) and the SCSI generic node of the
drive — `/dev/sgX`, which `lsblk -o NAME,MODEL` and `sg_map -i` will give you.

```sh
# 1. the symptom
sudo hdparm -I /dev/sdX | grep -E 'Model|Firmware'

# 2. the cause: protect flag + init-scan variables, straight out of controller RAM
sudo PYTHONPATH=/path/to/psychite/src \
     python3 tools/safe_dump.py /dev/sgX diag-protect
```

A drive in this repo's fault class answers like this:

```
IDENTIFY model='SATAFIRM   S11' firmware='SBFM21W1'
0x5c0cb5f0 [1] 04        protect flag: bit 2, and nothing else
0x5c0ceaac [1] 03        error unit at firmware block 3  (= physical block 12)
0x5c0ce6da [1] 05        system unit header found
0x5c0ce6db [1] 07        block map found
```

Four things have to hold: the flag is **exactly `04`**, the error-unit block is **not
`ff`**, and the system unit header and block map were **both found** (neither is `ff`).

If any other bit of the flag is set, or the header and map come back `ff`, **stop.** The
cause is something else, this repair does not apply, and erasing would be a guess. The
bit-by-bit meaning is in [Protect mode](docs/01-protect-mode.md).

Remember the ÷4 when you go from that output to a block number: firmware block 3 is
physical block 12.

## The short version

`SATAFIRM S11` is not a firmware corruption state. On this drive it was a single bit
in a RAM flag, set by one specific check at init:

- Byte `0x5C0CB5F0` in controller IRAM is a **protect-mode bitfield**. Any non-zero
  value makes `IDENTIFY` report `SATAFIRM S11`.
- Bit 2 is set by `FUN_60016c4c`, the system-area mount routine, when its scan finds
  a page whose OOB header matches the `ERROR_UNIT` magic.
- The drive had a real error unit: a 53-page log block the firmware wrote when an
  operation failed. Every boot found it and re-entered protect mode.
- **Erasing that block ended the condition permanently.**

Reading the flag live is enough to tell you *why* a drive is in protect mode, before
touching anything. `tools/safe_dump.py diag-protect` does exactly that.

Full detail: [Protect mode](docs/01-protect-mode.md).

## What is documented here

| Document | Contents |
|---|---|
| [01 - Protect mode](docs/01-protect-mode.md) | The flag, its bits, the init scan, the error unit, live diagnostics |
| [02 - NAND page format](docs/02-page-format.md) | OOB layout, page-type magics, frame entries, partial frames, block numbering |
| [03 - Repair procedure](docs/03-repair.md) | Step by step, with the interlocks that make it safe |
| [04 - What did not work](docs/04-what-did-not-work.md) | Dead ends, wrong hypotheses, and the method lesson |
| [05 - Tool reference](docs/05-tools.md) | Every parameter of every tool, and the environment variables |

## Findings that may be reusable

**Firmware block numbering is physical blocks ÷ 4.** When the firmware records
"block 3", that is physical block 12 in the VUC addressing used to read pages. A
firmware block is four internal units; the OOB CE-id field (byte 10) confirms the
grouping. This single factor blocked progress for a long time.

**pSLC vs MLC read mode is not optional.** A pSLC block read in MLC mode looks
*erased*. On this drive 4662 of 8768 blocks were misclassified that way and skipped
as empty; they held 38 GB of data, the entire system area, and the error unit. The
same mismatch also looked like "the controller hangs when reading system blocks".

**Psychite's CE encoding is wrong for this drive.** It uses the bit position within
`ce_bitmap` (0/4/8/12); values 4 and 12 silently re-read CE0/CE1 at page+2 instead of
selecting CE1/CE3. Correct encoding, verified against the OOB CE id:

```python
ce_raw = (((address >> 2) & 1) << 3) | ((address >> 3) & 1)   # 0->0, 4->8, 8->1, 12->9
```

**The VUC read path is not scrambled.** Commercial recovery vendors describe the
PS3111-S11 as applying XOR scrambling to NAND writes. Whatever happens at the cell
level, `READ_FLASH` over VUC returns plaintext: the error unit on this drive contained
a 176 KB copy of the firmware's own `sec2` section, and it matched our decrypted
firmware image byte for byte. There is no XOR key to extract on this path.

**Partial frames explain most "undecodable" data.** Bit 0 of byte 8 of an OOB frame
entry marks a partial frame. Across 263 sampled versions, a frame with that bit set
*never* contained the full 4 KB of its declared LBA. Reading those frames as if they
did produces high-entropy nonsense — which is easy to mistake for encryption.

**Where a partial frame's data belongs.** It holds a contiguous run of sectors, the
tail of its 4 KB unit, at offset 0 of the frame:

```
n     = run length of the bits equal to bit 0 of byte 9, starting at bit 0
shift = 8 - n
frame[0 .. n*512) == device sectors [LBA + shift, LBA + 8)
```

Verified against the repaired device by content hash: 60 of 60, 100%.

**The drive was not worn out — it was being switched off.** Once healthy, `smartctl -x`
reported 74999 power-on hours, 2368 power cycles, and **2358 `Power-Off_Retract_Count`**:
99.6% of those cycles ended in unexpected power loss. Life left 92%, zero read errors.
Together with a metadata block full and needing roll-over, and an erased page in the
middle of one firmware copy, that points at an interrupted system-area update. Run SMART
after any repair of this kind: if this is the pattern, the repair is not the fix, and the
drive will do it again. Detail in [Repair procedure](docs/03-repair.md).

## Tools

All of these wrap [Psychite](https://github.com/trulycrisp/psychite) and need it
installed. They are deliberately conservative: `safe_dump.py` is an allowlist in front
of the vendor command set, so a typo cannot reach an erase or a firmware write.

| Tool | Purpose |
|---|---|
| `tools/safe_dump.py` | Allowlist wrapper over Psychite. Diagnostics, raw page dump, system-area scan, gated erase |
| `tools/dump_runner.py` | Long-running dump driver: resume from manifest, auto-recovery from controller hangs |
| `tools/rebuild_image.py` | Rebuild a disk image from raw pages using OOB LBA tags. **Incomplete — see caveat** |
| `tools/ntfs_usage.py` | Read NTFS `$Bitmap` from a disk image without mounting it |
| `tools/scan_ntfs.py` | Count valid MFT records and index blocks in raw dumps |
| `ghidra/scripts/` | Load firmware sections at their real addresses; find and trace the protect flag |

Full parameter reference: [05 - Tool reference](docs/05-tools.md).

Useful `safe_dump.py` subcommands:

```
diag-protect      read the protect flag and the init-scan variables (read only)
sys-scan          re-classify page 0 of the system blocks the way the firmware does
dump              raw page dump with OOB, resumable
erase-block       erase one NAND block, behind three interlocks
restart           soft controller reset: reloads from NAND and re-runs init
product-history   vendor history (rejected on SBFM21.1, kept for other firmwares)
```

### Caveat on `rebuild_image.py`

It does **not** currently produce a mountable image, and the reason is worth stating.
On this drive the raw dump covered 77% of the volume's live clusters, but only 50% in
complete frames, because version ordering and partial-frame accounting are unsolved.
An NTFS volume missing a quarter of its used clusters does not mount. Repairing the
drive and letting its own firmware serve the data was the shorter path by a wide
margin. Treat this tool as a starting point, not a solution.

## Open problems

None of these blocked the recovery. The drive was repaired, imaged, and the image boots;
that line of work is finished. What follows is open for *other* paths, and it is worth
being clear about which.

### If the controller cannot be repaired

These three matter only when you must rebuild a volume from a raw dump alone — a dead
controller, a chip-off read, a fault outside the class this repo covers. When the
controller can be made to serve its own data, repairing it is the shorter path by a wide
margin, and none of this is on the critical path.

1. **Version ordering.** `(sequence, physical page index)` picks the correct version 42%
   of the time among complete frames. The ordering key is wrong and the right one is not
   known.
2. **Byte 10 of the frame entry.** Its low nibble repeats the sector count; the upper
   bits are undecoded.
3. **Non-run masks.** Byte 9 values that are neither a leading nor a trailing run
   (`0x38`, `0x70`, `0x83`, `0x78`) give a length inconsistent with the observed fill.

### Not investigated further

4. **The missing 23%.** Of the volume's live clusters, 23% were in no dumped page, after
   searching all 8768 block files for their content. This was recorded as unexplained
   while the dump was the only evidence available. It is no longer: the repaired drive
   can be queried directly, which is how the partial-frame rule was settled. The question
   is cheap to answer now and simply was not pursued.

### Independent of reconstruction

5. **Bit 3 of the protect flag.** Read together with bit 2 by `FUN_6000892c`; no setter
   located. This one has practical weight regardless of the path taken: `diag-protect`
   can report a drive held in protect mode by a bit whose cause nobody can name.

The method that cracked the others is worth copying: get a known-good copy of the same
device, locate content by hash, and read the rule off the result rather than inferring
it from statistics.

## Machine-readable summary

[`ps3111-s11.json`](ps3111-s11.json) carries the memory map, flag bits, diagnostic
variable addresses, page magics, OOB field offsets and the partial-frame rule, so other
tools can consume them without parsing prose.

`ghidra/scripts/LabelS11.java` applies the function and variable names to a freshly
loaded firmware image.

## Safety

Reading is cheap; writing is not. The order that worked:

1. Dump everything first, in the correct read mode, and verify it.
2. Read the protect flag and the init-scan variables. They tell you the cause.
3. Only then consider a write, and only one you can justify from the firmware.

`erase-block` refuses to run unless the target page carries the expected magic (read
through the same addressing the erase will use), a local backup of the block exists
and matches, and `--yes` is given.

Re-initialising the drive with MPTool or similar destroys the NAND state permanently.
Do not do it until you have a verified image.

## Credits

The hard part — the vendor command transport, the command set, the firmware container
format — is [Psychite](https://github.com/trulycrisp/psychite) by trulycrisp, and the
accompanying writeup
[Drive Firmware Security – Phison S11](https://trulycrisp.github.io/drivefirmware/phison_s11/).
Nothing here would exist without it.

Psychite is **not vendored** in this repository: it declares no licence, so it is not
redistributed. Install it from upstream.

## Licence

MIT, see [LICENSE](LICENSE). Applies to the code and documents in this repository
only.
