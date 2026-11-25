#!/bin/bash
# 28 Oct 2026: Emberwill end to end (ceremony, reboots, walk, Kindling) under ASan + UBSan,
# then every released transaction re-verified with embit. Run from the project root.
set -e
gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Wno-unused-result -Wno-unused-function -Wno-unused-parameter \
  -Isrc -Ilib/g0crypto -Itests -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 \
  -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 -DEMBER_HOST_DEBUG=1 \
  tests/host_ember_e2e.c src/ember.c src/ember_hdr.c src/ember_tx.c src/ember_plan.c src/ember_walk.c src/ember_life.c src/ember_store.c \
  src/antiexfil.c src/btc.c lib/g0crypto/sha256.c lib/g0crypto/sha512.c lib/g0crypto/ripemd160.c \
  lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  tests/host_secp_callbacks.c -o /tmp/g0_ember_e2e
/tmp/g0_ember_e2e "$@"
python3 -I tools/check_released.py /tmp/ember_released.txt
