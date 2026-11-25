#!/bin/bash
# Host test: lib/scp03 (G0 side) against se_sim.py (independent SCP03 card side).
cd "$(dirname "$0")"
gcc -Wall -Wextra -I../lib/scp03 -I../lib/aes128 host_scp03.c ../lib/scp03/scp03.c ../lib/aes128/aes128.c -o /tmp/host_scp03 || exit 1
KSE=000102030405060708090a0b0c0d0e0f
KDAILY=1111111111111111111111111111111111111111111111111111111111111111
# blob = IV || AES-256-CBC(KDAILY, IV, inner32); the sim's CipherOneShot decrypts it with KDAILY
read IV CT INNER < <(python3 - <<PY
import os
from Crypto.Cipher import AES
iv=os.urandom(16); inner=os.urandom(32)
ct=AES.new(bytes.fromhex("$KDAILY"),AES.MODE_CBC,iv).encrypt(inner)
print(iv.hex(),ct.hex(),inner.hex())
PY
)
run() {
  local d; d=$(mktemp -d); mkfifo "$d/c2s" "$d/s2c"
  TAMPER=${TAMPER:-0} KSE=$KSE KDAILY=$KDAILY BLOB=$IV$CT PCR=${PCR:-1} SIMLOG=/tmp/sim.log python3 se_sim.py <"$d/c2s" >"$d/s2c" &
  local sp=$!
  /tmp/host_scp03 $KSE $IV$CT $INNER $1 3>"$d/c2s" 4<"$d/s2c"; local rc=$?
  wait $sp 2>/dev/null; rm -rf "$d"; return $rc
}
fail=0
echo "== normal";                 run        || fail=1
echo "== wrong K_SE";             run badkey || fail=1
echo "== PCR locked (read must be refused 6986)"; PCR=0 run; echo "rc=$? (non-zero expected)"
echo "== tampered response (R-MAC must fail, rc -5)"; TAMPER=1 run; echo "rc=$? (non-zero expected)"
[ $fail = 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
