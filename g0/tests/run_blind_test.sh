#!/bin/bash
# 19 Oct 2026 (review C2): secp256k1 context blinding must not change any
# signature. Re-randomizes the context before every BIP-340 vector and checks
# the exact expected bytes. Run from the project root.
set -e
gcc -O1 -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 -Iinclude \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 \
  -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 \
  -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 -Wno-unused-function \
  tests/host_blind.c lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  -o /tmp/g0_blind
/tmp/g0_blind | tail -3
