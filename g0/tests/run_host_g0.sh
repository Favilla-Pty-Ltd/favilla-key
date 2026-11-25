#!/bin/bash
# Whole-G0 host harness (audit 21 Nov 2026). Builds ALL of src/main.c for the
# host (fake HAL, flash as a fixed mmap at 0x08000000, a fake SE051 that
# enforces the ESP32's object policies) and runs scenarios S1..S7 plus random
# attacker searches. Run from g0/.
#   bash tests/run_host_g0.sh                       all scenarios
#   ITERS=2000 SEED=7 bash tests/run_host_g0.sh     longer door-rule searches
#   S8ONLY=1 ITERS8=2000 bash tests/run_host_g0.sh  the raw attacker only (every command byte, every register)
set -e
H=tests/host_g0; OUT=/tmp/host_g0; mkdir -p $OUT
FIX=""
python3 -I $H/transform.py src/main.c $OUT/g0_main_host.c $FIX
cp $H/*.inc $H/*.h $OUT/
CF="-I$OUT -Isrc -Iinclude -Ilib/secp256k1/include -Ilib/secp256k1 -Ilib/g0crypto -Ilib/tinyaes -Ilib/scp03 -Ilib/p256m
    -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1
    -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1"
SRCS="src/antiexfil.c src/btc.c src/bip39_words.c src/ember.c src/ember_hdr.c src/ember_life.c src/ember_plan.c
      src/ember_store.c src/ember_tx.c src/ember_walk.c src/key_store.c src/p256_det.c src/totp.c
      lib/g0crypto/sha256.c lib/g0crypto/sha512.c lib/g0crypto/ripemd160.c lib/g0crypto/pbkdf2.c lib/tinyaes/aes.c
      lib/p256m/p256-m.c lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c"
gcc -g -O1 -w $FIX $CF -no-pie -fsanitize=address,undefined -fno-sanitize-recover=undefined $OUT/g0_main_host.c $H/fakese.c $SRCS -o $OUT/g0host
$OUT/g0host
