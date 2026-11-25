#!/usr/bin/env python3
"""
entropy_check.py — host-side analysis for hardware RNG source dumps.

Two modes:

  source   Characterise a raw byte dump from ONE entropy source.
           Health tests + SP 800-90B most-common-value min-entropy estimate.

             python3 entropy_check.py source se051.bin

  seeds    Collision / structure check across many generated seeds.
           One hex seed per line (or a raw file of fixed-width records).

             python3 entropy_check.py seeds fleet_seeds.txt --width 32

IMPORTANT
  - These tests FALSIFY. Passing proves only "not broken in the ways tested".
  - Run each source SEPARATELY. Mixing them hides a dead one.
  - For a defensible number, also run NIST's own SP 800-90B tool
    (github.com/usnistgov/SP800-90B_EntropyAssessment). This is a fast
    pre-filter, not a substitute.
  - The firmware that dumps raw entropy is an exfiltration feature.
    Separate build. Never ship it.
"""

import argparse
import collections
import math
import sys
import zlib


# ── health tests (mirror what firmware should do at runtime) ──────────────

def health_tests(data: bytes) -> list[tuple[str, bool, str]]:
    """Return [(name, passed, detail)] — the catastrophic-failure checks."""
    n = len(data)
    out = []

    out.append(("not all zero", any(data), "all bytes 0x00" if not any(data) else ""))
    out.append(("not all ones", not all(b == 0xFF for b in data), ""))

    counts = collections.Counter(data)
    top_byte, top_n = counts.most_common(1)[0]
    out.append((
        "no dominant byte",
        top_n / n < 0.02,
        f"0x{top_byte:02x} is {100*top_n/n:.2f}% of stream (expect ~0.39%)",
    ))

    out.append((
        "byte diversity",
        len(counts) > 250,
        f"{len(counts)}/256 distinct byte values seen",
    ))

    # longest run of one repeated byte
    longest, cur = 1, 1
    for i in range(1, n):
        cur = cur + 1 if data[i] == data[i - 1] else 1
        longest = max(longest, cur)
    out.append((
        "longest repeat run",
        longest < 12,
        f"{longest} identical bytes in a row",
    ))

    # compression: real entropy is incompressible
    ratio = len(zlib.compress(data, 9)) / n
    out.append((
        "incompressible",
        ratio > 0.98,
        f"compresses to {100*ratio:.1f}% of original",
    ))

    return out


# ── statistical estimates ────────────────────────────────────────────────

def shannon_bits_per_byte(data: bytes) -> float:
    n = len(data)
    counts = collections.Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def chi_square_uniform(data: bytes) -> tuple[float, float]:
    """Chi-square against uniform over 256 symbols. Returns (chi2, z-score).

    df = 255, so mean = 255 and sd = sqrt(2*255) ~= 22.58. |z| > 4 is a
    strong signal of non-uniformity (or of a stream that is suspiciously
    TOO uniform, which indicates a counter or a whitened low-entropy source).
    """
    n = len(data)
    expected = n / 256
    counts = collections.Counter(data)
    chi2 = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))
    z = (chi2 - 255) / math.sqrt(2 * 255)
    return chi2, z


def serial_correlation(data: bytes) -> float:
    """Lag-1 correlation. Near 0 for a good source."""
    n = len(data)
    if n < 2:
        return 0.0
    x = data[:-1]
    y = data[1:]
    mx = sum(x) / len(x)
    my = sum(y) / len(y)
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    dx = math.sqrt(sum((a - mx) ** 2 for a in x))
    dy = math.sqrt(sum((b - my) ** 2 for b in y))
    return num / (dx * dy) if dx and dy else 0.0


def mcv_min_entropy(data: bytes) -> float:
    """SP 800-90B section 6.3.1 Most Common Value estimate, per BYTE.

    Takes the 99% upper confidence bound on the most likely symbol, then
    min-entropy = -log2(p_upper). This is the IID-track estimator: it is
    only valid if the samples are independent. Camera pixels are NOT
    independent (spatial correlation), so treat camera numbers as an
    optimistic ceiling and confirm with NIST's non-IID track.
    """
    n = len(data)
    counts = collections.Counter(data)
    p_hat = counts.most_common(1)[0][1] / n
    p_upper = min(1.0, p_hat + 2.576 * math.sqrt(p_hat * (1 - p_hat) / (n - 1)))
    return -math.log2(p_upper)


# ── modes ────────────────────────────────────────────────────────────────

def mode_source(path: str) -> int:
    with open(path, "rb") as f:
        data = f.read()

    n = len(data)
    if n < 100_000:
        print(f"WARNING: only {n} bytes. Min-entropy estimates need >= 1e6 "
              f"samples to mean anything. Treat this as a smoke test.\n")

    print(f"=== {path} — {n:,} bytes ===\n")

    print("Health tests (the catastrophic-failure checks):")
    failed = 0
    for name, ok, detail in health_tests(data):
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  [{mark}] {name}{('  — ' + detail) if detail else ''}")

    chi2, z = chi_square_uniform(data)
    sc = serial_correlation(data)
    shannon = shannon_bits_per_byte(data)
    mcv = mcv_min_entropy(data)

    print(f"\nStatistics:")
    print(f"  Shannon entropy      {shannon:.4f} bits/byte   (8.0 ideal)")
    print(f"  Chi-square           {chi2:.1f}  z = {z:+.2f}   (|z| > 4 is suspicious)")
    print(f"  Serial correlation   {sc:+.6f}                 (0 ideal)")

    print(f"\nSP 800-90B MCV min-entropy estimate:")
    print(f"  {mcv:.4f} bits/byte  ->  {mcv/8*100:.1f}% efficiency")
    print(f"  Bytes needed for 256 bits of real entropy: {math.ceil(256/mcv)}")

    print()
    if failed:
        print(f"VERDICT: {failed} health test(s) FAILED — this source is broken.")
        return 1

    # Shannon is near-8 for any whitened stream, including a broken one.
    # The point of saying so explicitly is that a good-looking number here
    # is exactly what Coldcard's SHA-256 whitening produced for five years.
    print("VERDICT: no catastrophic failure detected.")
    print("  This does NOT establish the source has full entropy. A PRNG with")
    print("  a 32-bit seed passes every test above. Only cross-device collision")
    print("  testing (mode 'seeds') can catch a small-but-uniform space.")
    return 0


def mode_seeds(path: str, width: int) -> int:
    """Collision and structure check across many generated seeds."""
    raw = open(path, "rb").read()
    seeds = []

    # try hex-per-line first, fall back to fixed-width binary records
    try:
        for line in raw.decode("ascii").splitlines():
            line = line.strip()
            if line:
                seeds.append(bytes.fromhex(line))
    except (UnicodeDecodeError, ValueError):
        seeds = [raw[i:i + width] for i in range(0, len(raw) - width + 1, width)]

    n = len(seeds)
    if n < 2:
        print("Need at least 2 seeds.")
        return 1

    print(f"=== {path} — {n:,} seeds of {len(seeds[0])} bytes ===\n")

    # 1. exact collisions — ANY collision is catastrophic
    seen = {}
    collisions = []
    for i, s in enumerate(seeds):
        if s in seen:
            collisions.append((seen[s], i))
        seen[s] = i

    if collisions:
        print(f"  [FAIL] {len(collisions)} EXACT COLLISION(S) FOUND")
        for a, b in collisions[:5]:
            print(f"         seed {a} == seed {b}: {seeds[a].hex()}")
        print("\n  A collision in this few samples is proof of a broken RNG.")
        print("  True 128-bit entropy needs ~2^64 samples for a birthday hit.")
        return 1
    print(f"  [PASS] no exact collisions in {n:,} seeds")

    # 2. near-collisions — catches counters and correlated PRNG output
    def hamming(a, b):
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    bits = len(seeds[0]) * 8
    expected = bits / 2
    threshold = expected * 0.7          # 30% closer than chance
    near = []
    # O(n^2); fine to a few thousand seeds
    for i in range(n):
        for j in range(i + 1, n):
            d = hamming(seeds[i], seeds[j])
            if d < threshold:
                near.append((i, j, d))
    if near:
        print(f"  [FAIL] {len(near)} suspiciously similar pair(s) "
              f"(expect ~{expected:.0f} differing bits)")
        for a, b, d in near[:5]:
            print(f"         seed {a} vs {b}: only {d} bits differ")
        return 1
    print(f"  [PASS] no near-collisions (min pairwise distance is normal)")

    # 3. positional bias — catches a constant field, e.g. a zeroed SE
    #    contribution that XOR left untouched
    biased = []
    for pos in range(len(seeds[0])):
        col = collections.Counter(s[pos] for s in seeds)
        top, cnt = col.most_common(1)[0]
        if cnt / n > 0.05 and n >= 40:
            biased.append((pos, top, cnt / n))
    if biased:
        print(f"  [FAIL] {len(biased)} byte position(s) show a repeated value")
        for pos, val, frac in biased[:8]:
            print(f"         byte {pos}: 0x{val:02x} appears in {100*frac:.1f}% of seeds")
        return 1
    print(f"  [PASS] no positional bias across seeds")

    print("\nVERDICT: no fleet-level structure detected.")
    print("  Keep this corpus permanently. It is the only artefact that lets")
    print("  you retroactively answer 'was batch N affected'.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    p1 = sub.add_parser("source", help="characterise one raw entropy source")
    p1.add_argument("file")

    p2 = sub.add_parser("seeds", help="collision check across many seeds")
    p2.add_argument("file")
    p2.add_argument("--width", type=int, default=32,
                    help="bytes per seed if input is raw binary (default 32)")

    a = ap.parse_args()
    if a.mode == "source":
        return mode_source(a.file)
    return mode_seeds(a.file, a.width)


if __name__ == "__main__":
    sys.exit(main())
