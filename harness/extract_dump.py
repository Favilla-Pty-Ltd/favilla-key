#!/usr/bin/env python3
"""
extract_dump.py — pull raw entropy binaries out of a captured serial log.

    pio device monitor > serial.log      # run the FAVILLA_ENTROPY_DUMP build
    python3 extract_dump.py serial.log
    python3 entropy_check.py source SE051.bin

Writes one .bin per source found. Reports any gaps rather than papering over
them: a dump with dropped lines is not a sample you can draw conclusions
from, and silently concatenating around a gap is exactly the kind of quiet
degradation this whole exercise is about.
"""

import argparse
import binascii
import os
import re
import sys

BEGIN = re.compile(r"\[DUMP-BEGIN\]\s+source=(\S+)\s+bytes=(\d+)\s+chunk=(\d+)")
END   = re.compile(r"\[DUMP-END\]\s+source=(\S+)\s+bytes=(\d+)\s+failures=(\d+)\s+elapsed_ms=(\d+)")
DATA  = re.compile(r"^D:([0-9a-fA-F]+)\s*$")
FAIL  = re.compile(r"\[DUMP-FAIL\]\s+at offset (\d+)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile")
    ap.add_argument("-o", "--outdir", default=".", help="where to write the .bin files")
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)

    current = None       # (label, expected_bytes, chunk)
    buf = bytearray()
    bad_lines = 0
    se_failures = []
    results = []

    with open(a.logfile, "r", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\r\n")

            m = BEGIN.search(line)
            if m:
                if current:
                    print(f"  WARNING: source {current[0]} never ended "
                          f"(got {len(buf)} bytes) — log is truncated or interleaved")
                    results.append((current[0], bytes(buf), current[1], "TRUNCATED"))
                current = (m.group(1), int(m.group(2)), int(m.group(3)))
                buf = bytearray()
                bad_lines = 0
                se_failures = []
                continue

            m = FAIL.search(line)
            if m and current:
                se_failures.append(int(m.group(1)))
                continue

            m = END.search(line)
            if m and current:
                label, expected, _chunk = current
                status = "OK"
                if m.group(1) != label:
                    status = "LABEL-MISMATCH"
                if len(buf) != expected:
                    status = "SHORT"
                results.append((label, bytes(buf), expected, status))
                if se_failures:
                    print(f"  NOTE: {label} had {len(se_failures)} se_random "
                          f"failure(s) at offsets {se_failures[:5]}"
                          f"{' ...' if len(se_failures) > 5 else ''}")
                    print( "        Those regions were zero-filled. That is a"
                           " FINDING, not noise —")
                    print( "        a source that intermittently fails is a"
                           " source you cannot budget.")
                if bad_lines:
                    print(f"  WARNING: {label} had {bad_lines} unparseable"
                          f" data line(s) — likely serial corruption.")
                    print( "        Note: concurrent Serial writes on this"
                           " firmware can interleave and")
                    print( "        corrupt lines. Re-run with other logging"
                           " quiet if this is high.")
                current = None
                continue

            if current is not None:
                m = DATA.match(line)
                if m:
                    hexs = m.group(1)
                    if len(hexs) % 2:
                        bad_lines += 1
                        continue
                    try:
                        buf.extend(binascii.unhexlify(hexs))
                    except binascii.Error:
                        bad_lines += 1
                elif line.startswith("D:"):
                    # started as data but did not match — corrupted mid-line
                    bad_lines += 1

    if current:
        print(f"  WARNING: source {current[0]} never ended "
              f"(got {len(buf)} bytes) — log truncated")
        results.append((current[0], bytes(buf), current[1], "TRUNCATED"))

    if not results:
        print("No [DUMP-BEGIN] markers found.")
        print("Is this a FAVILLA_ENTROPY_DUMP build, and did the capture start"
              " before boot?")
        return 1

    print(f"\n{'source':<16} {'bytes':>10} {'expected':>10}  status")
    print("-" * 52)
    rc = 0
    for label, data, expected, status in results:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
        path = os.path.join(a.outdir, safe + ".bin")
        with open(path, "wb") as out:
            out.write(data)
        print(f"{label:<16} {len(data):>10} {expected:>10}  {status}")
        if status != "OK":
            rc = 1

    print("\nNext:")
    for label, _d, _e, _s in results:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
        print(f"  python3 entropy_check.py source {os.path.join(a.outdir, safe + '.bin')}")
    print("\nThe comparison that matters is ESP32-RF-OFF against ESP32-RF-ON.")
    print("Onboarding runs with radios down, so RF-OFF is the number that")
    print("describes what actually happens at seed generation.")
    print("\nReminder: delete these .bin files when the analysis is done, and")
    print("never merge the -DFAVILLA_ENTROPY_DUMP flag to a shippable branch.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
