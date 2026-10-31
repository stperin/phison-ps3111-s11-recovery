# Tool reference

Every parameter of every tool, with what it does and when you want it. For the method
behind them see the other documents; this one is the manual.

All Python tools need **3.10 or newer** — `safe_dump.py` annotates two attributes with
`bytes | None`, and an annotation on an attribute target is evaluated at runtime — and
have no dependency beyond the standard library and, for `safe_dump.py` and
`dump_runner.py`, [Psychite](https://github.com/trulycrisp/psychite).

## Conventions

**Two machines.** `safe_dump.py` runs on the host the drive is attached to (the
*target*), as root, with Psychite on `PYTHONPATH`. `dump_runner.py` runs on your
workstation and drives the target over ssh. Everything else is offline analysis and runs
wherever the dump files are.

**Block numbers are physical**, as `READ_FLASH` addresses them, in every tool here. The
firmware's own numbering is a quarter of that — see
[page format](02-page-format.md#block-numbering-divide-by-four). The one place the
firmware's numbering appears is the output of `diag-protect`, because that is the
firmware's variable being read.

**CE numbering.** `--ce` takes the `ce_bitmap` address: `0`, `4`, `8`, `12`. The tool
converts it to the raw value the controller wants. Psychite's own conversion is wrong for
this drive; `probe-ce` is there to prove which one your drive uses.

**Environment variables.**

| Variable | Used by | Meaning |
|---|---|---|
| `S11_TARGET` | `dump_runner.py` | ssh destination of the target, e.g. `user@192.0.2.10`. Default is the placeholder `user@TARGET-IP` |
| `PYTHONPATH` | `safe_dump.py` | must contain Psychite's `src/` |
| `S11_FW_DIR` | `AddS11Sections.java` | directory with the unpacked firmware sections |
| `S11_OUT` | `DecompileAt.java` | file to write the decompiled output to |
| `S11_LITERALS` | `TraceFlag.java` | comma-separated literal values to trace |
| `S11_TARGETS` | `FlagWrites.java` | comma-separated addresses to find writes to |

---

## `safe_dump.py`

```
safe_dump.py DRIVE [--log FILE] [--log-errors-only] ACTION [options]
```

An allowlist in front of Psychite. Every ATA command goes through `SafeDrive.command`,
which permits only:

- `IDENTIFY DEVICE`;
- `STANDBY IMMEDIATE` carrying the AP key (count `0x6F`, LBA `0xFAEFFE`), which arms
  exactly one vendor command;
- `READ`/`WRITE SECTORS NO RETRY` immediately after that key, and only with a VUC feature
  on the allowlist.

Writes — `SET_PARAMETER` included — are refused until a valid `SystemInfo` has been read
in the same session. That is the proof that the firmware is intercepting vendor commands
at all; without it a write would land on a real LBA and corrupt user data. Unlock and
`DOWNLOAD MICROCODE` need their own explicit flags on top.

### Global arguments

| Argument | Default | Meaning |
|---|---|---|
| `DRIVE` | — | `/dev/sgX`. Pass `-` for `receive` and `done-list`, which touch no device |
| `--log FILE` | `safe_s11.log` | JSONL log of every ATA command: feature, registers, result |
| `--log-errors-only` | off | log only failures and blocked commands. Worth it on a full dump, where the complete log runs to gigabytes |

### Read-only actions

| Action | Arguments | What it does |
|---|---|---|
| `identify` | — | `IDENTIFY DEVICE`: model and firmware strings. The cheapest way to see protect mode |
| `sysinfo` | `--raw FILE` | controller `SystemInfo`: CE count, dies, blocks, pages, sector size. `--raw` also dumps the undecoded structure |
| `info-block` | `--raw FILE` | the controller's info block |
| `flash-id` | — | NAND ID of every CE |
| `block-map` | `--out FILE` | the firmware's per-channel block map: `FTL_FREE`, `FTL_OPEN_*`, `FTL_CLOSED_*`, `FTL_META`, `SYSTEM` |
| `read-page` | `CE DIE BLOCK PAGE` `--pslc` `--out F` | one page. Writes `F.data` (16 KB) and `F.oob` (512 B) |
| `read-sram` | `ADDRESS SIZE` `--chunk N` `--out F` | controller RAM. Addresses accept `0x` notation. `--chunk` defaults to `0x1000`; lower it if the controller stalls. **Do not read the mask ROM at `0x5C0D8000` — it hangs the controller** |
| `probe-ce` | `CE_RAW BLOCK PAGE` `--pslc` `--out F` | reads with a **raw** CE value instead of the bitmap address, to work out your drive's encoding. Check OOB byte 10 against what you asked for |
| `diag-protect` | `--sram` | the protect flag and the init-scan variables. **Start here on a faulty drive.** `--sram` adds the block/sequence arrays and the scan's OOB buffer |
| `sys-scan` | `--ce` `--die` `--blocks` `--pslc` `--out` | re-classifies page 0 of each block exactly as the firmware's init scan does, printing the page type it would have decided. Defaults: `--ce all`, `--die 0`, `--blocks 0-99` |
| `product-history` | `--size N` `--show N` | vendor history log. **Rejected on SBFM21.1** (ABORT, error 4); kept because other firmwares answer it. `--size` bytes to read (default `512`), `--show` bytes to print (default `256`) |

### `dump` — the raw page dump

```
safe_dump.py /dev/sgX dump --out FILE [--ce all] [--die all] [--blocks all]
                           [--pages all] [--pslc] [--plan FILE] [--max-errors 3]
```

| Argument | Default | Meaning |
|---|---|---|
| `--out` | required | output file, or `-` to stream to stdout. **This is how you dump over ssh** |
| `--ce` | `all` | bitmap addresses: `0`, `4`, `8`, `12` |
| `--die` | `all` | die index |
| `--blocks` | `all` | ranges and lists: `0-99,200,512-1023` |
| `--pages` | `all` | same syntax. `0` alone is a fast survey of page 0 of every block |
| `--pslc` | off | **read in pSLC mode** (512 pages per block). Without it a pSLC block reads as erased. This flag is the single most common cause of a wasted dump |
| `--plan FILE` | — | a file (or `-`) of `skip\|only CE DIE BLOCK` and `skippage CE DIE BLOCK PAGE` lines. How `dump_runner.py` resumes and how it steps over a page that hangs the controller |
| `--max-errors` | `3` | consecutive ATA/ECC errors before giving up |

Receiving side, on your workstation:

```
safe_dump.py - receive OUTDIR     # reads the stream on stdin, writes ceN-bBBBBB.data/.oob
safe_dump.py - done-list OUTDIR   # prints the "ce die block" lines already complete
```

### Writing actions

Each refuses to run without `--yes`. The first three are volatile — a power cycle undoes
them. `erase-block` is not.

| Action | Arguments | What it does |
|---|---|---|
| `restart` | — | soft controller reset: reloads firmware from NAND and re-runs init. **Needed to see the effect of an erase**, since an S3 suspend is only a COMRESET and does not re-run the scan |
| `clear-protect` | `--yes` | zeroes the protect flag in RAM. `IDENTIFY` changes at once and **the drive still serves no data**: the decisions gated on that bit were taken at boot. Diagnostic only |
| `probe-reset-patch` | `--yes` `--restart` | patches the flag-setting store in RAM and tests whether it survives a reset. It does not — `WRITE_REGISTER` cannot reach the SRAM code region. Kept as a negative result |
| `unlock` | `--allow-engineering-dlmc` | the VUC unlock sequence, which writes controller status registers. The flag additionally permits `DOWNLOAD MICROCODE` with an empty engineering header |
| `read-firmware` | `--out` `--raw` `--psychite-example DIR` | extracts the installed firmware; enables `SEND_SEED` and `VERIFY_FLASH` for the duration. `--raw` saves header and sections without decoding |
| `engineering` | `--yes` | engineering-mode header via `DOWNLOAD MICROCODE`; writes no firmware. **Rejected in protect mode** |
| `update-firmware` | `FIRMWARE --sha256 HASH --yes` | segmented `DOWNLOAD MICROCODE`. **Writes to the drive.** The hash is mandatory and checked before anything is sent. Also rejected in protect mode |

### `erase-block` — the repair

```
safe_dump.py /dev/sgX erase-block --ce CE --block N --backup FILE.data --yes
                                  [--die 0] [--pslc] [--expect error-unit]
```

**Irreversible.** Three interlocks have to pass before a single byte is erased:

1. page 0 of the target carries the expected magic, read back **through the same
   addressing the erase will use** — not through your dump, which may have been taken
   with a different CE encoding;
2. a local backup of the block exists and matches what is on the drive;
3. `--yes` is present.

| Argument | Default | Meaning |
|---|---|---|
| `--ce` | required | bitmap address |
| `--block` | required | **physical** block number |
| `--die` | `0` | die index |
| `--pslc` | off | pSLC mode. The system area is pSLC: for an error unit you almost certainly want this |
| `--expect` | `error-unit` | magic required in page 0. Accepts `any`, or a literal like `0xffd00000`. **Changing this disables interlock 1** |
| `--backup` | required | the block's `.data` backup; the matching `.oob` must sit beside it |
| `--yes` | off | without it the tool stops after reporting what it would do |

After the erase, run `restart` and then `diag-protect` again. The flag should read `00`
and the error-unit variable `ff`.

---

## `dump_runner.py`

```
dump_runner.py OUTDIR --only FILE [--pslc] [--pages all]
                      [--on-fatal block|page] [--max-recoveries 50] [--skip-pages ...]
```

Runs on your workstation. It copies `safe_dump.py` to the target, starts a streaming dump
into `safe_dump.py receive`, and when the controller hangs it recovers the drive and
resumes from the manifest. A 105 GB dump needs this; by hand it is unmanageable.

Recovery is an S3 suspend with an RTC wake-up, then a SCSI delete plus rescan — a plain
COMRESET does not bring this controller back.

| Argument | Default | Meaning |
|---|---|---|
| `OUTDIR` | required | output directory. Holds `manifest.txt` (blocks done), `fatal.txt` (pages that hung), `retry.txt` (blocks to redo) |
| `--only FILE` | required | the work list: lines of `ce die block`. `safe_dump.py - done-list` produces its complement |
| `--pslc` | off | pSLC mode for this pass |
| `--pages` | `all` | page range. Use `0-511` in a pSLC pass: a pSLC block has only 512 |
| `--on-fatal` | `block` | what a controller hang costs. `block` abandons the rest of the block and queues it in `retry.txt` — usually a pSLC block being read in MLC, which the second pass fixes. `page` skips only that page |
| `--max-recoveries` | `50` | recovery attempts before stopping |
| `--skip-pages` | empty | pages never to read, per CE: `1:1022-1023`. A workaround for the wrong CE encoding; with the correct one it is unnecessary |

The two-pass shape this is built for:

```sh
dump_runner.py dump-mlc  --only all-blocks.txt
dump_runner.py dump-pslc --only dump-mlc/retry.txt --pslc --pages 0-511 --on-fatal page
```

---

## `rebuild_image.py`

```
rebuild_image.py index DUMPDIR [DUMPDIR...] --out index.bin
rebuild_image.py image index.bin --out disk.img
```

Rebuilds a disk image from the dump using the LBA tags in the OOB. **It does not produce
a mountable image** — see the caveat in the [README](../README.md#caveat-on-rebuild_imagepy)
and [open problems](../README.md#open-problems). Treat it as a starting point.

| Sub-command | Argument | Meaning |
|---|---|---|
| `index` | `DUMPDIR...` | one or more dump directories, scanned for `*.oob` |
| | `--out` | the index: every (LBA → page, frame, version) it found |
| `image` | `index` | an index produced above |
| | `--out` | the assembled image |

`index` prints duplicate statistics before writing anything, deliberately: the
version-ordering key is the unsolved part, and the statistics are what tell you how much
the choice matters on your dump.

---

## Offline analysis

### `ntfs_usage.py`

```
ntfs_usage.py IMAGE PARTITION_START_SECTOR
```

How full an NTFS volume is, **without mounting it** — which matters when the image is
incomplete and the kernel driver would be the wrong tool to point at it. Reads the boot
sector, then MFT record 6 (`$Bitmap`), follows its data runs and counts set bits: one bit
per cluster, 1 = in use.

Both arguments are positional and required. The start sector comes from
`sgdisk -p IMAGE` or `fdisk -l IMAGE`. It prints sector and cluster size, MFT record
size, volume size, MFT location, and clusters used/free with the percentage.

### `scan_ntfs.py`

```
scan_ntfs.py DUMPDIR [DUMPDIR...]
```

Counts valid MFT records and directory indexes across `*.data` files. "Valid" means the
`FILE` signature at 1024-byte alignment, allocated size 1024 or 4096, flags in 0..3, and
a plausible update-sequence offset — **without those checks the signature alone produces
false positives inside user data**, which is exactly how a drive can look like it has
lost its MFT when it has not. Progress every 500 files.

### `scan_ntfs_strings.py`

```
scan_ntfs_strings.py DUMPDIR [DUMPDIR...]
```

The cross-check for the above, independent of record layout: searches for NTFS structural
signatures — `NTFS    `, and `$MFT`, `$MFTMirr`, `$LogFile`, `$Bitmap`, `$BadClus`,
`$Secure`, `$I30`, `bootmgfw` in UTF-16LE, plus `BOOTMGR`. If the MFT were truly gone the
metafile names would be missing too. Prints counts and up to four example files per
signature.

---

## Ghidra scripts

Headless, in this order. The firmware on NAND is encrypted; disassembly needs the
decrypted image, from IRAM or from Psychite's `read_firmware.py` + `firmware_tool.py unpack`.

```sh
analyzeHeadless PROJ NAME -import sec0.bin -scriptPath ghidra/scripts \
    -preScript AddS11Sections.java -postScript LabelS11.java
```

| Script | Environment | What it does |
|---|---|---|
| `AddS11Sections.java` | `S11_FW_DIR` | maps the sections at their real addresses: `sec0` → `0x5C0E0000`, `sec1` → `0x5C0C8000`, `sec2` → `0x60000400`. **Nothing resolves without this** |
| `LabelS11.java` | — | applies the names in this repo: `system_area_mount`, `identify_device`, `protect_flag` and the rest. Addresses are specific to SBFM21.1 — verify before trusting them on another build |
| `FindProtectRefs.java` | — | every reference to the protect flag |
| `FlagWrites.java` | `S11_TARGETS` | writes to the given addresses, comma-separated. How the four flag bits were attributed to their setters |
| `TraceFlag.java` | `S11_LITERALS` | traces the given literal values, comma-separated. Used to find the page magics in code |
| `DecompileAt.java` | `S11_OUT` | decompiles whichever functions contain the addresses passed as script arguments |

---

## Known defects

The tools carry their known defects as `TODO` comments in the source, rather than in a
list that drifts out of date:

```sh
grep -rn TODO tools/
```

At the time of writing there are ten, the three worth knowing before you run anything:
the segmented-`DOWNLOAD MICROCODE` allowlist compares bytes with a substring search rather
than by position; the `allow_*` privilege flags are raised and lowered without
`try/finally` in five commands, so an exception leaves the filter more permissive than it
should be; and `receive` will replace a complete block file with a partial one if the same
block is dumped twice with different page ranges.
