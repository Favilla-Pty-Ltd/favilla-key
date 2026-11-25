#!/bin/bash
# libFuzzer + ASan + UBSan over the real VAULT handler, TOTP (v17) included.
#   MBT=<mbedtls src> bash tests/run_fuzz_vault.sh [seconds]   (default 120). Run from g0/.
set -e
SECS=${1:-120}
MBT=${MBT:-../mbt/src}
bash tests/run_vault_test.sh > /dev/null   # the extraction the harness includes (/tmp/extracted_pk.inc), and the suite itself
mkdir -p /tmp/fz_vault tests/corpus_vault
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -Wno-unused-function \
  -Iinclude -Ilib/g0crypto -Ilib/scp03 -Ilib/tinyaes -Isrc -Itests -I/tmp -I$MBT/include \
  -Ilib/p256m tests/fuzz_vault.c src/totp.c src/p256_det.c lib/p256m/p256-m.c lib/g0crypto/sha256.c lib/tinyaes/aes.c $MBT/library/libmbedcrypto.a -o /tmp/fz_vault/fz
/tmp/fz_vault/fz tests/corpus_vault -max_len=600 -max_total_time=$SECS -print_final_stats=1 2>&1 | tail -8
