#!/usr/bin/env python3
"""Dump lungo con recupero automatico del controller.

Gira su questo PC. Lancia safe_dump.py dump sul target in streaming verso safe_dump.py receive.
Se il controller si pianta (riga FATAL):
  - registra la pagina in OUTDIR/fatal.txt;
  - modo "block" (default): salta il resto del blocco e lo mette in OUTDIR/retry.txt
    (di solito un blocco pSLC letto in MLC: va riletto con --pslc in una seconda passata);
  - modo "page": salta solo quella pagina;
  - recupera l'SSD (sospensione S3 con sveglia RTC, poi delete + rescan SCSI) e riparte dal manifest.

Uso:
  tools/dump_runner.py --only FILE OUTDIR            # FILE: righe "ce die block"
  tools/dump_runner.py --only retry.txt --pslc --pages 0-511 --on-fatal page OUTDIR_PSLC
"""

import os
import argparse
import pathlib
import re
import subprocess
import sys
import time

TARGET = os.environ.get("S11_TARGET", "user@TARGET-IP")  # es. S11_TARGET=user@192.0.2.10
PSYCHITE = "/run/live/medium/live/psychite/src"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15"]
HERE = pathlib.Path(__file__).resolve().parent
# /dev/sgX dell'SSD (porta ata3): può cambiare dopo un rescan
FIND_SG = 'SG=$(for s in /sys/class/scsi_generic/*; do readlink -f $s/device | grep -q /ata3/ && echo /dev/$(basename $s); done)'


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, file=sys.stderr, flush=True)


def ssh(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([*SSH, TARGET, cmd], capture_output=True, text=True, timeout=timeout)


def wait_ssh(limit: int = 300) -> bool:
    end = time.monotonic() + limit
    while time.monotonic() < end:
        try:
            if ssh("true", timeout=20).returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(5)
    return False


def recover() -> bool:
    log("recupero SSD: sospensione S3 di 20 s")
    ssh(
        'sudo sh -c "echo 0 > /sys/class/rtc/rtc0/wakealarm; echo +20 > /sys/class/rtc/rtc0/wakealarm; '
        'nohup sh -c \\"sleep 2; echo mem > /sys/power/state\\" >/dev/null 2>&1 &"'
    )
    time.sleep(15)
    if not wait_ssh():
        log("target non raggiungibile dopo la sospensione")
        return False
    r = ssh(
        'sudo sh -c "echo 1 > /sys/block/sda/device/delete" 2>/dev/null; sleep 2; '
        'sudo sh -c "echo \\"- - -\\" > /sys/class/scsi_host/host2/scan"; sleep 8; '
        f'{FIND_SG}; cd /home/user && sudo PYTHONPATH={PSYCHITE} python3 safe_dump.py $SG '
        "--log /home/user/safe_s11.log --log-errors-only sysinfo | grep -c protected_mode",
        timeout=120,
    )
    ok = r.returncode == 0 and r.stdout.strip() == "1"
    log("SSD di nuovo raggiungibile" if ok else f"recupero fallito: {r.stdout} {r.stderr}")
    return ok


def healthy() -> bool:
    try:
        r = ssh(
            f"{FIND_SG}; cd /home/user && sudo PYTHONPATH={PSYCHITE} python3 safe_dump.py $SG "
            "--log /home/user/safe_s11.log --log-errors-only sysinfo | grep -c protected_mode",
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0 and r.stdout.strip() == "1"


def read_lines(path: pathlib.Path) -> list[tuple[int, ...]]:
    if not path.exists():
        return []
    return [tuple(map(int, line.split())) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("outdir")
    p.add_argument("--only", required=True, help='file con righe "ce die block"')
    p.add_argument("--pslc", action="store_true")
    p.add_argument("--pages", default="all")
    p.add_argument("--on-fatal", choices=("block", "page"), default="block")
    p.add_argument("--max-recoveries", type=int, default=50)
    p.add_argument(
        "--skip-pages",
        default="",
        help="pagine da non leggere per CE, es. '1:1022-1023' (con la codifica CE corretta non serve)",
    )
    args = p.parse_args()

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    fatal_file, retry_file = outdir / "fatal.txt", outdir / "retry.txt"
    targets = read_lines(pathlib.Path(args.only))
    skip_pages: dict[int, list[int]] = {}
    for part in filter(None, args.skip_pages.split(",")):
        ce, _, rng = part.partition(":")
        lo, _, hi = rng.partition("-")
        skip_pages[int(ce)] = list(range(int(lo), int(hi or lo) + 1))
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", str(HERE / "safe_dump.py"), f"{TARGET}:/home/user/"], check=True)

    recoveries = 0
    while True:
        done = set(read_lines(outdir / "manifest.txt"))
        retry = set(read_lines(retry_file))
        fatal = read_lines(fatal_file)
        todo = [t for t in targets if t not in done and t not in retry]
        log(f"blocchi: {len(targets)} totali, {len(done)} fatti, {len(retry)} da rifare in pSLC, {len(todo)} da fare")
        if not todo:
            log("finito")
            return
        plan = "".join(f"only {c} {d} {b}\n" for c, d, b in todo)
        plan += "".join(f"skippage {c} {d} {b} {pg}\n" for c, d, b, pg in fatal)
        plan += "".join(
            f"skippage {c} {d} {b} {pg}\n" for c, d, b in todo for pg in skip_pages.get(c, ())
        )

        remote = (
            f"{FIND_SG}; cd /home/user && sudo PYTHONPATH={PSYCHITE} python3 safe_dump.py $SG "
            f"--log /home/user/safe_s11.log --log-errors-only dump --plan - --pages {args.pages} "
            f"{'--pslc ' if args.pslc else ''}--out -"
        )
        dump = subprocess.Popen([*SSH, TARGET, remote], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        receive = subprocess.Popen(
            [sys.executable, str(HERE / "safe_dump.py"), "-", "receive", str(outdir)], stdin=dump.stdout
        )
        dump.stdout.close()
        dump.stdin.write(plan.encode())
        dump.stdin.close()
        fatal_at = None
        last_progress = ""
        n = 0
        for raw in dump.stderr:
            line = raw.decode(errors="replace").rstrip()
            if m := re.match(r"FATAL (\d+) (\d+) (\d+) (\d+)", line):
                fatal_at = tuple(map(int, m.groups()))
            elif line.startswith("blocco "):
                n += 1
                last_progress = line
                if n % 50 == 0:
                    log(last_progress)
            else:
                log(f"target: {line}")
        dump.wait()
        receive.wait()
        log(f"dump terminato con codice {dump.returncode}; ultimo: {last_progress}")

        if dump.returncode == 0:
            continue  # rilegge il manifest: se manca qualcosa riparte, altrimenti "finito"
        if fatal_at:
            ce, die, block, page = fatal_at
            with open(fatal_file, "a") as f:
                f.write(f"{ce} {die} {block} {page}\n")
            if args.on_fatal == "block":
                with open(retry_file, "a") as f:
                    f.write(f"{ce} {die} {block}\n")
            log(f"controller bloccato a ce {ce} die {die} blocco {block} pagina {page}")
        recoveries += 1
        if recoveries > args.max_recoveries:
            raise SystemExit("troppi recuperi: mi fermo")
        if not fatal_at:
            log("interruzione senza FATAL (rete?): attendo il target e controllo l'SSD")
            if not wait_ssh():
                raise SystemExit("target non raggiungibile")
        if fatal_at or not healthy():
            if not recover():
                raise SystemExit("recupero non riuscito: serve intervento manuale (spegnere e riaccendere il target)")


if __name__ == "__main__":
    main()
