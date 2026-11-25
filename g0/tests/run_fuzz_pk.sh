#!/bin/bash
# libFuzzer + ASan + UBSan over the real PKSIGN handler (G0 v16 signer, v18 hedged).
#   MBT=<mbedtls src> bash tests/run_fuzz_pk.sh [seconds]   (default 120). Run from g0/.
set -e
SECS=${1:-120}
MBT=${MBT:-../mbt/src}
bash tests/run_pk_test.sh > /dev/null   # the extraction the harness includes, and the suite itself
mkdir -p /tmp/fz_pk tests/corpus_pk
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -Wno-unused-function \
  -Iinclude -Ilib/g0crypto -Ilib/scp03 -Ilib/tinyaes -Ilib/p256m -Isrc -Itests -I/tmp -I$MBT/include \
  tests/fuzz_pk.c src/p256_det.c lib/p256m/p256-m.c lib/g0crypto/sha256.c lib/tinyaes/aes.c $MBT/library/libmbedcrypto.a -o /tmp/fz_pk/fz
/tmp/fz_pk/fz tests/corpus_pk -max_len=100 -max_total_time=$SECS -print_final_stats=1 2>&1 | tail -8
