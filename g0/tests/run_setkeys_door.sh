#!/bin/bash
# 22 Nov 2026 host test for audit #53 (G0 v21): SETKEYS only while the door is
# UNSET. Extracts the REAL do_setkeys from src/main.c. Run from the g0 folder.
set -e
python3 - <<'PY'
src=open("src/main.c").read()
i=src.index("static int do_setkeys(void) {"); j=src.index("static void wipe_transient(void) {", i)
open("/tmp/extracted_setkeys.inc","w").write(src[i:j])
PY
gcc -O1 -Wall -Wno-unused-function -Iinclude -Ilib/g0crypto -I/tmp tests/host_setkeys_door.c lib/g0crypto/sha256.c -o /tmp/g0_setkeys_door
/tmp/g0_setkeys_door
