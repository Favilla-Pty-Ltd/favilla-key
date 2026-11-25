#!/bin/bash
# 19 Oct 2026 host test for review findings 3 (MODE_PCR delete/recreate) and
# 4 (door fails open). Extracts the REAL source from src/main.c. Run from the
# project root.
set -e
python3 - <<'PY'
src=open("src/main.c").read()
def grab(a, b):
    i=src.index(a); return src[i:src.index(b, i)]
# MODEDEL must not be accepted as a command any more
cw=grab("static void commit_write(size_t n) {", "case G0_REG_HASH_IN:")
assert "G0_CMD_MODEDEL:" not in cw, "MODEDEL is still accepted by commit_write"
assert "do_modedel" not in src, "do_modedel still present"
parts=[grab("#define WIPE_N 15", "\n/* WIPEKEYS gate"),
       grab("static int do_door(uint8_t want) {", "static void finish(int rc) {")]
open("/tmp/extracted34.inc","w").write("".join(parts))
print("PASS  MODEDEL: not in the accepted command list, no handler")
PY
gcc -O1 -Wall -Iinclude -Ilib/g0crypto -Ilib/scp03 -I/tmp tests/host_finding34.c lib/g0crypto/sha256.c -o /tmp/g0_f34
/tmp/g0_f34
