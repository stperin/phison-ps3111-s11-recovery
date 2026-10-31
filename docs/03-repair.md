# Repair procedure

What follows is what was actually done, in order. It applies when `diag-protect` shows
**bit 2 and only bit 2**, and the scan reports a system unit header and a block map.
Any other combination means a different cause; do not erase anything.

> Erasing a NAND block is irreversible. Take and verify a full raw dump first.

## 0. Host setup

The drive hangs some systems during boot. Two mitigations, both needed, neither
individually proven:

```
systemd.mask=smartmontools.service ahci.mobile_lpm_policy=1
```

On the failing drive, `smartd` querying it during boot preceded a `hardreset failed`
and `ata3.00: disable device` at a consistent 98.64 s. With both options the drive
stayed up. After repair, `smartctl` worked without trouble, which suggests the
fragility belonged to protect mode rather than to SMART — not proven.

When the controller does hang, it comes back with an S3 suspend plus a SCSI rescan:

```sh
sudo sh -c 'echo 0 > /sys/class/rtc/rtc0/wakealarm; echo +20 > /sys/class/rtc/rtc0/wakealarm;
            nohup sh -c "sleep 2; echo mem > /sys/power/state" >/dev/null 2>&1 &'
# after resume:
sudo sh -c 'echo 1 > /sys/block/sdX/device/delete'
sudo sh -c 'echo "- - -" > /sys/class/scsi_host/hostN/scan'
```

`dump_runner.py` does this automatically between retries.

## 1. Dump everything, in the right mode

```sh
safe_dump.py /dev/sgX dump --ce all --blocks 0-2191 --out dump.bin
```

Blocks whose page 0 looks erased in MLC mode **must be retried in pSLC** before you
conclude they are empty. Check the OOB page index against the read order to confirm the
mode is right. Getting this wrong hides the fault.

Expect zero read errors on a drive whose problem is logical. 105 GB were read here with
none.

## 2. Diagnose, read-only

```sh
safe_dump.py /dev/sgX diag-protect
safe_dump.py /dev/sgX sys-scan --ce 0-1 --blocks 0-35 --pslc
```

`diag-protect` gives the reason bits and the block numbers. `sys-scan` re-classifies
page 0 of the system blocks using the firmware's own rules, so you can see the error
unit directly. Remember the ÷4: the firmware's block 3 is your block 12.

Do not proceed unless the flag is exactly `0x04` and both metadata blocks were found.

## 3. Erase the error unit

One block per CE that carries it. `erase-block` enforces three interlocks: the target
page must carry the `ERROR_UNIT` magic *read through the same addressing the erase will
use*, a local backup of the block must exist and match, and `--yes` must be given.

```sh
# dry run first: performs every check, writes nothing
safe_dump.py /dev/sgX erase-block --ce 0 --block 12 --pslc --backup ce0_b00012.data

# then, with --yes
safe_dump.py /dev/sgX erase-block --ce 0 --block 12 --pslc --backup ce0_b00012.data --yes
safe_dump.py /dev/sgX erase-block --ce 1 --block 12 --pslc --backup ce1_b00012.data --yes
```

Expected output per block:

```
page 0 word0 = 0xffd00000 (ERROR_UNIT)
  backup: ... word0 matches
  ERASE done
  after: word0 = 0x00000000 (LBA 0x0), OOB byte8 = 0xff
```

`byte8 = 0xff` means erased. `word0 = 0x00000000` is the value that does *not* trigger
the protect check. **If it reads `0xffffffff` instead, stop**: on that read path an
erased page presents as all-ones, which still matches the error-unit mask, and the
trigger would survive.

Erase every CE that carries one. The scan reads them all; one survivor re-sets the bit.

## 4. Restart the controller

An S3 suspend is **not enough** — it is a COMRESET, and the init scan runs on
controller reset. Use the VUC soft reset:

```sh
safe_dump.py /dev/sgX restart
```

Expected:

```
before: flag=04, IDENTIFY model='SATAFIRM   S11'
0x5c0cb5f0 [1] 00   flag = 0x00: no bits set
0x5c0ceaac [1] ff   error unit block -> NONE
after:  IDENTIFY model='SPCC M.2 SSD' firmware='SBFM21.1'
```

`0x5C0CEAAC = 0xff` is the proof that matters: init re-ran and found no error unit. The
flag is zero because the diagnosis is clean, not because you wrote it. The repair is
persistent — the error unit is no longer on the NAND.

## 5. Rescan and verify

```sh
sudo sh -c 'echo 1 > /sys/block/sdX/device/delete'
sudo sh -c 'echo "- - -" > /sys/class/scsi_host/hostN/scan'
lsblk -o NAME,SIZE,MODEL,FSTYPE,LABEL
```

Then verify at increasing depth: partition table, filesystem boot sector, and the MFT
itself. The MFT start LBA can be computed from the NTFS boot sector; a valid first
record begins `46 49 4c 45 30 00 03 00` (`"FILE0"`).

## 6. Image it immediately

The condition that caused the failure is usually still present — on this drive the
metadata blocks were still full, with no successor. Take the image before anything
else, over the fastest path available. Streaming over Wi-Fi ran at 11 MB/s; writing to
a locally attached USB disk ran at 126 MB/s.

```sh
dd if=/dev/sdX of=/mnt/usb/disk.img bs=1M conv=noerror,sync status=progress
```

`conv=noerror,sync` zero-fills a whole block on a read error, so check the log for
errors afterwards. With errors, redo with `ddrescue` and a mapfile; `dd` loses up to
1 MiB of recoverable data per bad sector.

`conv=sync` pads the final block, so truncate the image to the exact device size
afterwards, or the backup GPT header will not sit at the last sector.

## 7. Verify the image boots

With an overlay, so the image is never written:

```sh
qemu-img create -f qcow2 -F raw -b disk.img overlay.qcow2
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
qemu-system-x86_64 -enable-kvm -machine q35 -m 4096 -smp 2 -nic none \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -drive file=overlay.qcow2,if=none,id=d0,format=qcow2 \
  -device ahci,id=ahci -device ide-hd,drive=d0,bus=ahci.0 \
  -display gtk
```

UEFI firmware is required for a GPT/EFI install; a BIOS machine type will not boot it.
Use `-nic none`: a recovered system may carry remote-access software that starts on its
own and would appear online with the same identity as the real machine.

`INACCESSIBLE_BOOT_DEVICE` is a plausible outcome when the virtual hardware differs
from the original, and does not by itself mean the image is bad. Verify the filesystem
instead.

## After the repair: find out why

`smartctl -x` is worth running once the drive is healthy. On this drive:

```
  9 Power_On_Hours           74999      8.6 years
 12 Power_Cycle_Count         2368
192 Power-Off_Retract_Count   2358      unexpected power loss
231 (life left)                 92
```

**2358 unclean shutdowns out of 2368 power cycles.** With a metadata block full and
needing roll-over, and one of the four firmware copies carrying an erased page in the
middle, the picture is consistent: an interrupted system-area update.

If that is the cause, the drive is not the problem and the repair is not the fix. A
clean shutdown path or a UPS is.
