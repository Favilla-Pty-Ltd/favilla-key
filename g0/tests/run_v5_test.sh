#!/bin/bash
# v5 / v5.1 host test: runs the REAL fetch_blob_se / g0_read_mode_pcr / seed_inner_crypt
# from src/main.c (extracted verbatim) against a fake SE that holds MODE_PCR.
# Run from the project root.
set -e
python3 - <<'PY'
src=open("src/main.c").read()
def grab(a, b):
    i=src.index(a); return src[i:src.index(b, i)]
parts=[grab("static const uint8_t INNER_PKT_MAGIC[4]", "\n")+"\n",
       grab("static const uint8_t MODE_CONST_SPENT[32]", "};")+"};\n",
       grab("static int g0_read_mode_pcr(scp03_session_t *s, uint8_t out[32]) {", "/* Generic doors (30 Oct 2026): do_modedoor(d)"),
       grab("static void kseed_key(uint8_t key[32]) {", "/* SEEDSEAL: onboarding only."),
       grab("/* v5.1: refused while a seed is stored here", "/* ===========================================================================\n * v4 (24 Sep 2026)")]
open("/tmp/extracted.inc","w").write("".join(parts))
PY
gcc -O1 -Iinclude -Ilib/g0crypto -Ilib/tinyaes -Ilib/scp03 -I/tmp tests/host_v5_fetch.c lib/g0crypto/sha256.c lib/tinyaes/aes.c -o /tmp/g0_v5_fetch 2>/dev/null
/tmp/g0_v5_fetch
