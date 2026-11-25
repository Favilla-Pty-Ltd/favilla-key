#!/bin/bash
# libFuzzer + ASan + UBSan over the anti-exfil INIT/FINISH state machine (real handlers).
#   bash tests/run_fuzz_antiexfil.sh [seconds]   (default 120). Run from the project root.
set -e
SECS=${1:-120}
python3 - <<'PY'
import re
src=open("src/main.c").read()
def span(a,b): i=src.index(a); j=src.index(b,i); return src[i:j]
defs="\n".join(l for l in src.splitlines() if re.match(r'#define (G0_CMD_|G0_REG_|AE_IN_LEN|AE_TIMEOUT_MS|BTCSIGN_VER|MSGSIGN_VER_AE|BTC_OUT_LEN|KG0_LEN)', l))
open("/tmp/extracted_ae_defs.inc","w").write(defs+"\n")
open("/tmp/extracted_ae_state.inc","w").write(span("/* ── anti-exfil state (27 Oct 2026)", "\n\n"))
open("/tmp/extracted_ae_sign.inc","w").write(span("/* 19 Oct 2026: the identity's x-only pubkey", "static int do_pubkey(void) {"))
open("/tmp/extracted_ae_btc.inc","w").write(span("/* BTCSIGN_INIT (anti-exfil, 27 Oct 2026)", "static int do_sessiontest(void) {"))
open("/tmp/extracted_ae_door.inc","w").write(span("/* 1 = this command may run under the door currently held", "/* 19 Oct 2026 (review finding 4)"))
PY
mkdir -p /tmp/fz_ae tests/corpus_antiexfil
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
  -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable \
  -Isrc -Ilib/secp256k1/include -Ilib/secp256k1/src -Ilib/secp256k1 -Ilib/g0crypto -Iinclude -I/tmp \
  -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 \
  -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 \
  -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 \
  tests/fuzz_antiexfil.c src/antiexfil.c src/btc.c lib/g0crypto/sha256.c lib/g0crypto/sha512.c lib/g0crypto/ripemd160.c \
  lib/secp256k1/src/secp256k1.c lib/secp256k1/src/precomputed_ecmult.c lib/secp256k1/src/precomputed_ecmult_gen.c \
  -o /tmp/fz_ae/fz
/tmp/fz_ae/fz tests/corpus_antiexfil -max_len=600 -max_total_time=$SECS -print_final_stats=1 2>&1 | tail -12
