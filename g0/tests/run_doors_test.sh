#!/bin/bash
# 30 Oct 2026 host test for generic doors (passkey door spec v1.0 section 4).
# Extracts the REAL source from src/main.c and src/ember_glue.inc and runs it
# against a fake SE that models MODE_PCR (read, reset, extend). Run from the
# project root.
set -e
python3 - <<'PY'
src=open("src/main.c").read(); emg=open("src/ember_glue.inc").read()
def grab(t, a, b):
    i=t.index(a); return t[i:t.index(b, i)]
parts=[grab(src,"static void life_save(void) {", "/* v5.1 seed store."),
       grab(src,"static const uint8_t MODE_CONST_SPENT[32]", "static int do_modereset(void) {"),
       grab(src,"static int g0_read_mode_pcr(scp03_session_t *s, uint8_t out[32]) {", "/* MODEDEL RETIRED"),
       grab(emg,"static int em_door_permits(", "/* ISR side"),
       grab(src,"static int do_door(uint8_t want) {", "static void finish(int rc) {")]
open("/tmp/extracted_doors.inc","w").write("".join(parts))
cw=grab(src,"static void commit_write(size_t n) {", "case G0_REG_HASH_IN:")
assert "G0_CMD_DOORPASSKEY:" in cw and "G0_CMD_MODEDOOR:" in cw, "new commands not accepted by commit_write"
disp=grab(src,"        switch (cmd) {\n        case G0_CMD_SIGN_INIT:", "default:               rc = -1;")
assert "rc = do_modedoor(g_door)" in disp, "MODEDOOR must mint for the HELD door"
print("PASS  commit_write accepts DOORPASSKEY and MODEDOOR; dispatch mints for the held door only")
PY
gcc -O1 -Wall -Wno-unused-function -Iinclude -Ilib/g0crypto -Ilib/scp03 -I/tmp tests/host_doors.c lib/g0crypto/sha256.c -o /tmp/g0_doors
/tmp/g0_doors
