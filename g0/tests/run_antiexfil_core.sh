#!/bin/bash
# 27 Oct 2026: anti-exfil cores (src/antiexfil.c) on the host. Run from the project root.
set -e
gcc -O1 -Wall -Wextra -Wno-unused-result -Isrc -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 -Ilib/g0crypto -Iinclude \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 \
  -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 \
  -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 -Wno-unused-function -Wno-unused-parameter \
  tests/host_antiexfil_core.c src/antiexfil.c lib/g0crypto/sha256.c lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  -o /tmp/g0_antiexfil_core
/tmp/g0_antiexfil_core "$@"
