#!/bin/bash
# Bounded model checking of lib/scp03 + the MODE_PCR TLV walk with CBMC 5.95.
# Checks: array bounds, pointer validity/overflow, signed overflow, div-by-zero,
# and unwinding assertions (so the loop bounds below are PROVED sufficient).
# Deliberately NOT --conversion-check / --unsigned-overflow-check: the code's
# intentional uint32->uint8 byte splits and `while (n--)` idioms trip those and
# they are not memory-safety properties.
# Bounds: response length 0..514 (transport cap); havoc/wipe loops unwound to 531.
cd "$(dirname "$0")"
F="--bounds-check --pointer-check --pointer-overflow-check --signed-overflow-check --div-by-zero-check --unwinding-assertions --slice-formula"
INC="-I../lib/scp03 -I../lib/aes128"
U="--unwindset adv_xfer.0:516,wipe.0:1100,havoc.0:531,mode_pcr_tlv_walk.0:50"
run() { echo "== $1 (unwind $2)"; timeout ${3:-1200} cbmc $INC -D$1 $F $U --unwind $2 scp03_proof.c aes_stub.c 2>&1 | grep -E "VERIFICATION|FAILURE|\*\* [0-9]+ of" | head -20; }
run PROOF_TAG1 130
run PROOF_TLV  50
run PROOF_OPEN 40
run PROOF_CMD  40 2400
