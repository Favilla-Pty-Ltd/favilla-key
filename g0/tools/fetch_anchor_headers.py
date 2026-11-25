#!/usr/bin/env python3
"""fetch_anchor_headers.py: the header dump make_anchor.py needs, without a
Bitcoin node (20 Nov 2026).

Fetches every header from S (a difficulty-period start) to A = S + COUNT - 1
from two public explorers, mempool.space and blockstream.info, and refuses
unless both give the same bytes for every height. make_anchor.py then
re-checks links, proof of work, constant nBits and median time itself, so a
wrong source cannot become an anchor: it would need real mining at mainnet
difficulty.

  python g0/tools/fetch_anchor_headers.py                 (latest period start at least 110 deep)
  python g0/tools/fetch_anchor_headers.py --start 975744  (a chosen period start)

Writes headers.txt (one hex header per line) and prints the make_anchor.py
command to run next. Standard library only.
"""
import argparse, json, sys, time, urllib.request

SRC = ("https://mempool.space/api", "https://blockstream.info/api")
COUNT = 16          # 11 or more give make_anchor.py real timestamps for median time (no BENCH padding)

def get(url):
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "favilla-anchor/1"})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode().strip()
        except Exception as e:
            if attempt == 3: raise SystemExit("could not fetch %s: %s" % (url, e))
            time.sleep(2 + 2 * attempt)

def header(base, h):
    bh = get("%s/block-height/%d" % (base, h))
    if len(bh) != 64: raise SystemExit("%s: odd block hash for height %d: %r" % (base, h, bh))
    hx = get("%s/block/%s/header" % (base, bh))
    if len(hx) != 160: raise SystemExit("%s: odd header for height %d" % (base, h))
    return hx.lower()

ap = argparse.ArgumentParser()
ap.add_argument("--start", type=int, help="first height, a multiple of 2016")
ap.add_argument("--out", default="headers.txt")
a = ap.parse_args()

tips = [int(get(b + "/blocks/tip/height")) for b in SRC]
tip = min(tips)
S = a.start if a.start is not None else (tip - 110 - COUNT) // 2016 * 2016
if S % 2016: raise SystemExit("--start must be a multiple of 2016")
A = S + COUNT - 1
if tip - A < 100: raise SystemExit("height %d is only %d deep; pick an earlier period start" % (A, tip - A))
print("tip %d (mempool.space %d, blockstream %d); fetching %d..%d from both" % (tip, tips[0], tips[1], S, A))
lines = []
for h in range(S, A + 1):
    x, y = header(SRC[0], h), header(SRC[1], h)
    if x != y: raise SystemExit("the two explorers DISAGREE at height %d: stop, do not use this dump" % h)
    lines.append(x); print("  %d ok" % h)
open(a.out, "w").write("\n".join(lines) + "\n")
print("\nwrote %s (%d headers, both explorers agree). Next:" % (a.out, len(lines)))
print("  python g0/tools/make_anchor.py --start %d %s > g0/include/ember_anchor.h" % (S, a.out))
