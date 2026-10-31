# Protect mode: what `SATAFIRM S11` actually is

Addresses and function names below are from firmware `SBFM21.1`, loaded into Ghidra as
Xtensa LE with sections at their runtime addresses (see `ghidra/scripts/AddS11Sections.java`):
`sec0` at `0x5C0E0000`, `sec1` at `0x5C0C8000`, `sec2` at `0x60000400`.

## The flag

`IDENTIFY` is produced by `FUN_60004c4c`. It reports the real model and firmware
unless the byte at **`0x5C0CB5F0`** is non-zero, in which case it reports
`SATAFIRM S11` / `SBFM21W1`.

The byte is a bitfield of *reasons*, not a single flag:

| Bit | Set by | Meaning |
|---|---|---|
| 0 | `FUN_6003bde8` | NAND context at `+0xfec` non-zero |
| 1 | `FUN_60056864` | Hardware pin/register (`reg+0x31c` bit 9), polarity from config |
| 2 | `FUN_60016c4c` | **System-area scan found an `ERROR_UNIT` page** |
| 3 | — | Read together with bit 2 by `FUN_6000892c`; setter not located |

It is read live: clearing it changes the `IDENTIFY` response immediately, with no
reset. That is a useful diagnostic and a misleading one — see below.

## The init scan

`FUN_60016c4c` mounts the system area. It walks blocks in ascending order on each CE,
reads page 0, and classifies it by the **first u32 of the OOB** (OOB entry 0, bytes
0-3, little endian), which it copies into a buffer at `0x50001200 + slot*0x100`:

```c
value = *(u32 *)(0x50001200 + slot * 0x100);

if ((~value & 0xFFD00000) == 0) {        /* ERROR_UNIT: a MASK test, not equality */
    *(u8 *)0x5C0CEAAC = block;           /* remember where */
    *(u8 *)0x5C0CB5F0 |= 4;              /* protect mode */
    break;
}
if (value == 0xFFA00000) { /* SYSTEM_UNIT_HEADER */ }
if (value == 0x3FB10200) { /* BLOCK_MAP        */ }
```

Two things matter here.

**The error-unit test is a mask, not a comparison.** `(~value & 0xFFD00000) == 0` means
"every bit of `0xFFD00000` is present". `0xFFFFFFFF` satisfies it, so in principle an
erased page would too. On this drive it does not, because unwritten pages read back as
`0x00000000` through the VUC path — confirmed empirically: firmware blocks 1, 2 and 6
were unwritten and the recorded block was 3, the real error unit.

**The scan does not abort.** It sets the bit and continues. The function returns
success if it finds both a system unit header and a block map. So the FTL metadata can
be perfectly healthy and the drive still refuses to serve data: bit 2 alone is enough.

## Live diagnostics

Every variable the scan writes stays in IRAM and can be read over VUC without writing
anything. `safe_dump.py diag-protect` reads them:

| Address | Size | Meaning |
|---|---|---|
| `0x5C0CB5F0` | 1 | Protect bitfield |
| `0x5C0CEAAC` | 1 | Block where `ERROR_UNIT` was seen |
| `0x5C0CE6DA` | 1 | Block of the `SYSTEM_UNIT_HEADER` found (`0xff` = none) |
| `0x5C0CE6DB` | 1 | Block of the `BLOCK_MAP` found (`0xff` = none) |
| `0x5C0CE9AB` | 1 | Scan limit (starts at 100, then from config) |
| `0x5C0CE6B4` | 1 | CE count |
| `0x5C0CEAE8` | 4 | CE bitmap |
| `0x6005CD00` | 12 | Block numbers: `[0..5]` system unit headers, `[6..11]` block maps |
| `0x6005CD10` | 48 | Sequence numbers for the above |
| `0x50001200` | 0x400 | The scan's OOB buffer, 4 slots of 0x100 |

On the failing drive, before any write:

```
IDENTIFY model='SATAFIRM   S11' firmware='SBFM21W1'
0x5c0cb5f0 [1] 04        <- only bit 2
0x5c0ceaac [1] 03        error unit at firmware block 3
0x5c0ce6da [1] 05        system unit header found
0x5c0ce6db [1] 07        block map found
0x5c0ce9ab [1] 08        scan covers firmware blocks 0..7
```

Both metadata blocks found, exactly one reason bit set. That is a complete diagnosis
from read-only commands, and it is what justified the erase.

## Why clearing the flag is not a repair

Writing `0` to `0x5C0CB5F0` over VUC makes `IDENTIFY` report the real model
immediately — and `dd` still reads zeros. The flag is the *symptom*. By the time you
clear it, the boot-time decisions gated on bit 2 have already been taken.

Nor does a soft reset help on its own: it reloads the sections from NAND, re-runs the
scan, finds the error unit again, and sets the bit again.

The sequence that works is: remove the cause on the NAND, then reset so init re-runs.

## The error unit

Magic `0xFFD00000` in OOB entry 0, with the low bits carrying a record index
(`0xFFD00000`, `0xFFD00001`, …). On this drive it occupied one block per CE on CE0 and
CE1, 53 of 512 pages written. The sub-type is in the second OOB u32 (`0xFF` plus a tag):

| Tag | Pages | Contents |
|---|---|---|
| `0x111111` | 1 | Configuration record, starts `49 44 aa 00` ("ID") — NAND geometry and timings |
| `0x222222` | 2 | 101 records of 0x58 bytes: copies of the NAND command descriptor |
| `0x555555` | 36 | Zero-filled, reserved |
| `0x666666` | 14 | 176 KB of `sec2` as it stood in SRAM |

The 101 descriptor records hold a fixed command (`0x00440021`), an index rising from
`0x1b` to `0x7f`, and two linear ramps (steps `0x40` and `2`). That shape — fixed
command, parameters stepping regularly — reads as a **read-retry sweep**: the firmware
retrying with shifted reference voltages. It gave up after 101 attempts, wrote the
error unit, and dumped its code section.

The `0x666666` pages are worth two separate notes. They match the decrypted firmware
byte for byte, which both validates a firmware extraction and proves the VUC read path
is unscrambled. And their variable region is a snapshot of controller state at the
moment of the panic: `0x6005CD00 = 05 ff ff ff ff ff | 07 ff` — the mount had
*succeeded* when the failure happened.
