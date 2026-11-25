#!/bin/bash
# 28 Oct 2026: plan chain vs the embit model, then every signature re-verified by embit.
set -e
gcc -O1 -Wall -Wextra -Isrc -Ilib/g0crypto -Itests -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 \
  -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 -Wno-unused-function -Wno-unused-parameter \
  tests/host_ember_plan.c src/ember_plan.c src/ember_tx.c lib/g0crypto/sha256.c lib/g0crypto/ripemd160.c \
  lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  tests/host_secp_callbacks.c -o /tmp/g0_ember_plan
/tmp/g0_ember_plan "$@"
python3 -I tools/check_signed.py /tmp/ember_signed.txt
