# What did not work

Dead ends, with the measurements that closed them. Several were pursued for a long
time; a few were wrong conclusions stated with more confidence than the evidence
supported. They are recorded because the negative results are reusable and because the
pattern behind them is the most transferable part of this work.

## Repair approaches that failed

**`DOWNLOAD MICROCODE`** — rejected in protect mode, both for a firmware update and
for the engineering-mode header. ABORT, error 4, status 0x71. No loader can be injected
this way while the drive is in protect mode.

**Patching the protect check in RAM** — the plan was to no-op the store at
`0x60017003` that sets bit 2. `WRITE_REGISTER` cannot write the SRAM code region
`0x6001xxxx`; it works at `0x5C0Cxxxx` only. The write silently fails. Dead.

**Clearing the flag** — works, and is not a repair. `IDENTIFY` changes immediately but
`dd` still reads zeros, because the decisions gated on bit 2 were taken at boot.

**Erasing the error unit, first attempt** — abandoned early because the magic
`0xFFD00000` appeared in no dump and reads of system blocks hung the controller. Both
observations were artefacts of reading pSLC blocks in MLC mode. The approach was
correct; the data was wrong. Reopening it was what fixed the drive.

## The "encrypted payload" that was not

A large fraction of frames, when read as 4 KB of their declared LBA, contain
high-entropy data with a recurring 8-byte prefix. This was treated as an encoded
payload needing a decoder. **It is not encoded.** Those are partial frames; reading
them that way compares unrelated bytes.

Every one of these was measured and excluded:

| Hypothesis | Result |
|---|---|
| XOR with a key, correctly aligned to valid sectors, known plaintext | XOR of plaintext and ciphertext has entropy **7.36** |
| Short repeating key (Vigenère) | Index of coincidence peaks at every multiple of 3 (L=3 → 0.0179 vs 0.0039 uniform), but the modal key per class (`0ffcc0`) yields neither zeros nor `FILE` |
| Bit reordering: even/odd bits, 2-bit pairs, 12-bit symbols, Gray decode, nibble swap, bit reversal | Entropy stays 7.17-7.32 in all six |
| Bit-level misalignment | No `FILE` at any of 8 shifts, either direction, nor bit-reversed |
| Already-compressed data | zlib still reduces the payload to 69%; an ordinary frame to 78% |
| Tables in the firmware | The recurring patterns (`ffcc00`, `3ff003`, `7ee007`, `ff8811`) appear nowhere in `sec0/1/2` |
| Wrong read mode | OOB physical page index matches read order on every block tested, both modes |
| Uncorrectable ECC | Same distribution of corrected bits (OOB byte 8) as ordinary pages |

### Two "fingerprints" that were artefacts

Do not reuse these. They were recorded as characteristic of the format and are not:

- **Bytes concentrated on 2-bit-aligned masks** (`fc`, `c0`, `0f`, `03`, `f0`, `3f`).
  Measured: 66.6% of adjacent bit pairs equal in a "mystery" frame, 26.8% of bytes with
  all pairs equal — against **66.4% and 33.6% in an ordinary data frame**. It is a
  property of binary data in general.
- **A dominant 3-byte period.** An ordinary frame containing plain x86-64 code scores
  0.189 at distance 3. A sample filter built on this threshold selected x86 code: one
  "mystery candidate" began `48 89 54 24 30`, i.e. `mov [rsp+0x30], rdx`.

### What settled it

Ground truth. Sixty LBAs taken from the dump, read from the repaired drive, compared
against **every** version of them in the dump:

| Outcome | n |
|---|---|
| A version matches byte for byte, at exactly the expected frame offset | 16 |
| The drive now reads all zeros (LBA deallocated; the dump holds stale data) | 18 |
| No version matches | 26 |

The 16 matches land at offset 0 of the expected frame, no shift: the LBA decoding and
the entry-to-frame mapping are correct. Correlating byte 8 against those outcomes gave
the partial-frame flag, and with it the explanation for every failed test above.

## Reconstruction from the raw dump

Measured in distinct 4 KB units, not frames — counting frames inflates everything,
because hot LBAs appear many times:

| | units | % of device | % of live data |
|---|---|---|---|
| covered by any frame | 7 817 315 | 26.7% | **77%** |
| covered by a complete frame | 5 078 853 | 17.3% | **50%** |

The volume was 34.8% full (41.5 GB of 119.3 GB), read from the NTFS `$Bitmap`. So the
dump held roughly three quarters of the live data — far better than "a quarter of the
device" suggests, and still not enough: an NTFS volume missing a quarter of its used
clusters does not mount.

Version ordering by `(sequence, physical page index)`, restricted to complete frames,
picks the correct version **42%** of the time. That is an open problem, bounded anyway
by what is present.

Partial-frame placement, by contrast, **is now solved** (see
[page format](02-page-format.md)) — and it was solved by the same method that solved
everything else: not by analysing the frames, but by locating their sectors on a known
device by content hash, then reading the rule off the result.

**23% of live clusters are not in the dump at all** — consistent with the 26 ground-truth
LBAs whose content was found nowhere, after searching all 8768 block files. This is
unexplained.

## External sources

Nearly everything findable about this controller's data format comes from one
commercial recovery vendor's marketing pages, which contradict each other (a key
derived from model and chip ID in one place, a two-layer "dynamic XOR" in another).
The one concrete claim — XOR scrambling on NAND writes — was **disproved from our own
data**: the error unit contained a 176 KB copy of the firmware's `sec2`, and it matched
the decrypted firmware byte for byte through the same VUC read path.

Academic literature covers FTL design generally ([LeaFTL](https://jianh.web.engr.illinois.edu/papers/leaftl-asplos2023.pdf),
and a feasibility study on [reverse engineering commercial SSD firmware](https://dants.github.io/papers/frvrs-hotos-2019.pdf))
but nothing on sub-page packing or spare-area layout for a specific controller. No
open-source project covers it.

## The pattern

Every high-value result came from **checking an assumption against something already
known**: read mode verified against the OOB page index, the ÷4 factor verified against
a RAM variable, the partial-frame flag verified against the repaired drive, coverage
cross-validated by two independent routes that agreed to within half a point.

Every dead end came from **looking for structure in statistics with no reference**:
entropy, periods, indices of coincidence, de-interleavings.

The "encrypted payload" hypothesis survived as long as it did because of how it was
being tested. Each negative result — not XOR, not a reordering, not compressed — was
read as "then it is a more complicated encoding" rather than as evidence against the
premise. A chain of exclusions that narrows forever without ever questioning the set it
started from.

The turning point was not a discovery. It was the moment the repaired drive became an
oracle that could be queried.
