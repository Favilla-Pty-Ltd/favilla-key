#!/usr/bin/env python3
"""
extract_reboot.py — pull the per-boot seed samples out of a reboot-loop log.

    pio device monitor > reboot.log        # FAVILLA_ENTROPY_REBOOT_TEST build
    python3 extract_reboot.py reboot.log -o entropy/
    python3 entropy_check.py seeds entropy/reboot_seeds.txt

Each boot prints one line:

    R:<index>:<mask>:<64 hex chars>      a successful draw
    R:<index>:FAIL:mask=<mask>           generateSeedEntropy returned false

Reports gaps in the index sequence rather than silently concatenating around
them. A missing boot is a lost sample, not a problem — but a missing RANGE
usually means the capture dropped, and you want to know that before drawing
conclusions from the count.
"""

import argparse
import os
import re
import sys
from collections import Counter

LINE = re.compile(r"^R:(\d+):([0-9A-Fa-f]{2}):([0-9a-fA-F]{64})\s*$")
FAIL = re.compile(r"^R:(\d+):FAIL:mask=([0-9A-Fa-f]{2})\s*$")
DONE = re.compile(r"\[REBOOT-TEST\] COMPLETE — (\d+) samples")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile")
    ap.add_argument("-o", "--outdir", default=".")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)

    samples = {}          # index -> hex
    failures = []         # (index, mask)
    masks = Counter()
    completed = None

    with open(a.logfile, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = LINE.match(line)
            if m:
                idx = int(m.group(1))
                masks[m.group(2).upper()] += 1
                samples[idx] = m.group(3).lower()
                continue
            m = FAIL.match(line)
            if m:
                failures.append((int(m.group(1)), m.group(2)))
                continue
            m = DONE.search(line)
            if m:
                completed = int(m.group(1))

    if not samples and not failures:
        print("No R: lines found.")
        print("Is this a FAVILLA_ENTROPY_REBOOT_TEST build?")
        return 1

    idxs = sorted(samples)
    lo, hi = idxs[0], idxs[-1]
    expected = hi - lo + 1
    missing = expected - len(idxs)

    print(f"samples captured : {len(samples)}")
    print(f"index range      : {lo}..{hi}")
    if missing:
        gaps, run_start, prev = [], None, None
        for i in range(lo, hi + 1):
            if i not in samples:
                if run_start is None:
                    run_start = i
                prev = i
            elif run_start is not None:
                gaps.append((run_start, prev)); run_start = None
        if run_start is not None:
            gaps.append((run_start, prev))
        print(f"MISSING          : {missing} boot(s) in {len(gaps)} gap(s)")
        for g0, g1 in gaps[:6]:
            print(f"                   {g0}" + (f"..{g1}" if g1 != g0 else ""))
        print("                   Single gaps are lost lines and harmless.")
        print("                   A long run usually means the capture dropped.")

    if failures:
        print(f"\nDRAW FAILURES    : {len(failures)}  <-- THIS IS A FINDING")
        print("  generateSeedEntropy() returned false on these boots. On a")
        print("  healthy device that should never happen. Indices:")
        print("   ", [i for i, _ in failures][:12])

    print(f"\nsource mask distribution:")
    for mk, c in sorted(masks.items()):
        note = {"03": "both sources healthy",
                "01": "SE only — ESP32 failed its health check",
                "02": "ESP32 only — SHOULD BE IMPOSSIBLE (SE is mandatory)"}.get(mk, "")
        print(f"  0x{mk}  {c:>5}  {note}")
    if "02" in masks:
        print("  ^ mask 0x02 means the SE did not contribute but generation")
        print("    proceeded. That would be a fail-closed regression.")

    if completed is not None:
        print(f"\ndevice reported the run COMPLETE at {completed} samples")

    out = os.path.join(a.outdir, "reboot_seeds.txt")
    with open(out, "w") as f:
        for i in idxs:
            f.write(samples[i] + "\n")
    print(f"\nwrote {len(idxs)} seeds -> {out}")
    print(f"\nNext:\n  python3 entropy_check.py seeds {out}")
    print("\nAny exact collision, near-collision, or positional bias is")
    print("CONCLUSIVE evidence of a broken generator. A clean result proves")
    print("it is not broken THIS way — it does not prove full entropy. That")
    print("needs cross-DEVICE testing at provisioning.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
