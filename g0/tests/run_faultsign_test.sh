#!/bin/bash
# 19 Oct 2026: verify-before-release + fresh aux in the G0 Nostr signer.
# Extracts the REAL do_sign() from src/main.c. Run from the project root.
set -e
python3 - <<'PY'
src=open("src/main.c").read()
i=src.index("/* 19 Oct 2026: the identity's x-only pubkey"); j=src.index("static int do_ecdh(void) {", i)
open("/tmp/extracted_sign.inc","w").write(src[i:j])
a=src.index("/* \u2500\u2500 anti-exfil state (27 Oct 2026)"); b=src.index("\n\n", a)
open("/tmp/extracted_ae_state.inc","w").write(src[a:b])
PY
gcc -O1 -Isrc -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 -Ilib/g0crypto -Iinclude -I/tmp \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 \
  -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 \
  -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 -Wno-unused-function -Wno-unused-result -Wno-unused-parameter \
  tests/host_faultsign.c lib/g0crypto/sha256.c lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  -o /tmp/g0_faultsign
/tmp/g0_faultsign
