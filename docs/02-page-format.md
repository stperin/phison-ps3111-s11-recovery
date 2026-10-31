# NAND page and OOB format

Geometry on this drive, from the controller's own `SYSTEM_INFO`: 4 CEs, 1 die each,
**2192 blocks per die**, 1024 pages per block, 32 sectors (16 KB) per page. 8768
blocks in total. A page carries 16 KB of data plus 512 bytes of OOB.

## Block numbering: divide by four

**Firmware block number = physical block number ÷ 4.** The firmware's "block 3" is
physical block 12 in the addressing used by `READ_FLASH`.

A firmware block is four internal units. The OOB CE-id field (byte 10) makes this
visible: physical blocks 32, 33, 34, 35 carry CE ids 0, 1, 2, 3, and blocks 0-3 of the
next CE carry 4, 5, 6, 7. The FTL unit occupies all four; the firmware copies, the
error unit, the system unit header and the block map occupy only the first.

Getting this wrong costs a lot of time: the firmware reports a block number that does
not exist in your dump's numbering, and nothing lines up.

## Read mode: pSLC and MLC are not interchangeable

Bit 15 of the LBA register of `READ_FLASH` selects pSLC. A pSLC block has 512 usable
pages; an MLC block has 1024.

**A pSLC block read in MLC mode looks erased.** That is the failure mode to watch for:
you conclude the block is empty and skip it. On this drive 4662 of 8768 blocks were
skipped that way. They contained 38 GB of data, the whole system area, and the error
unit that was causing the fault.

The same mismatch produced a second false conclusion — "reading system blocks hangs the
controller" — which was really just the wrong mode.

Verify the mode by checking that the OOB physical page index (bytes 14-15, big endian,
divided by `0x40`) equals the read order. On a correct read it does, in both modes.

The pSLC region on this drive is the **SLC write cache**: 4662 blocks covering only
1.9% of the volume's distinct 4 KB units, with an average of 11 versions per unit (one
LBA in the `$MFT` region had 195). Cold data lives in the MLC blocks, with 1.7×
duplication.

## OOB layout

512 bytes, as sixteen 16-byte entries.

### Entry 0 — page header

| Offset | Size | Meaning |
|---|---|---|
| 0 | u32 LE | LBA of the first frame, **or a page-type magic** |
| 4 | u32 LE | Superblock sequence. High byte `0xFF` for user pages; otherwise a sub-type tag |
| 8 | u8 | ECC corrected bits. **`0xFF` = page never written** |
| 10 | u8 | CE id (the `ce_bitmap` address) |
| 14-15 | u16 BE | Physical page index × `0x40` |

Byte 8 is the cheapest "is there data here" test, and byte 10 is the cross-check that
tells you whether your CE encoding is actually selecting the CE you asked for.

### Entries 1-4 — one per 4 KB frame

| Offset | Size | Meaning |
|---|---|---|
| 0 | u32 LE | LBA in 512-byte sectors. `0x1FFFFFE8` = empty frame |
| 8 | u8 | Flags. **Bit 0 set = partial frame** |
| 9 | u8 | Sector bitmap / payload length |
| 10 | u8 | Further offset/length field, not fully decoded |
| 12-15 | u32 | CRC |

## Page-type magics (OOB entry 0, first u32)

| Value | Type |
|---|---|
| `0x31113111` | Firmware header |
| `0x55AA55AA` | Firmware code |
| `0xFFA00000` | System unit header |
| `0x44505354` | System unit data (`"TSPD"`) |
| `0x3FB10200` | Block map |
| `0x3FB10400` | Product history |
| `0xFFB00000` | FTL / statistics unit |
| `0xFFD00000` | **Error unit** (low bits = record index) |

System-area layout on this drive, identical on CE0 and CE1 (CE2 and CE3 have none):

| Physical block | Firmware block | Type | Pages written |
|---|---|---|---|
| 0, 4 | 0, 1 | Firmware header + code (two copies) | 46-47 / 512 |
| 12 | 3 | **Error unit** | 53 / 512 |
| 20 | 5 | System unit header | 512 / 512 (full) |
| 28 | 7 | Block map | 512 / 512 (full) |
| 32-35 | 8 | FTL / statistics unit | 336 / 512 |

The FTL unit is *not* an L2P table: 2811 of its 4096 u32 are `0xFFFFFFFF` and the rest
are short counters. There is no stored logical-to-physical map to recover — the
firmware rebuilds it by scanning the OOB LBA tags, which is exactly what any
reconstruction tool has to do.

Both metadata blocks being completely full, with no successor block anywhere in the
scanned range, is consistent with a failure during the roll-over to a new metadata
block.

## Partial frames

This is the part that is genuinely incompletely decoded, and the part that makes naive
image reconstruction fail.

**Bit 0 of byte 8 marks a partial frame.** Ground truth across 263 sampled versions,
comparing against the repaired drive:

| byte 8 | differs | matches |
|---|---|---|
| `0xb1`, `0xd1`, `0xe1` (odd) | 263 | **0** |
| `0xb0`, `0xd0` (even) | 262 | 28 |

A frame with the bit set *never* holds the full 4 KB of its declared LBA. When a frame
does match, it always has byte 8 even, byte 9 in `{0x00, 0xff}`, and byte 10 `0x00` —
and the data sits at exactly the expected offset, with no shift.

**Payload length.** In a partial frame the payload occupies a whole number of 512-byte
sectors at the start of the frame; the remainder is `0x78` fill. Verified on 3973 of
4008 frames with trailing fill: the fill starts at a multiple of 512.

Byte 9 encodes that length as *the length of the run of bits equal to bit 0, starting
at bit 0*:

| byte 9 | bits | payload sectors |
|---|---|---|
| `0x03` | `00000011` | 2 |
| `0x0f` | `00001111` | 4 |
| `0x1f` | `00011111` | 5 |
| `0x7f` | `01111111` | 7 |
| `0xfc` | `11111100` | 2 |
| `0xf8` | `11111000` | 3 |
| `0xf0` | `11110000` | 4 |
| `0xe0` | `11100000` | 5 |

That rule explains 90% of frames with fill. It fails on non-contiguous or offset masks
(`0x38`, `0x70`, `0x83`, `0x78`), all of which measure 6-7 payload sectors — either the
rule is incomplete or the fill detector over-counts when real `0x78` bytes end the
payload.

**What is still unknown:** which sectors of which LBA a partial frame actually carries.
Byte 10 is presumably part of that answer. Until it is decoded, those frames cannot be
placed into a reconstructed image.

## Why partial frames look like encryption

Reading a partial frame as though it were 4 KB of its declared LBA compares unrelated
bytes. The result has ~7.3 bits/byte of entropy and no recognisable structure, which is
indistinguishable from ciphertext if you do not have a known plaintext to check against.

That mistake drove a long detour. The relevant tests and their results are in
[What did not work](04-what-did-not-work.md).
