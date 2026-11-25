#!/bin/bash
# libFuzzer + ASan + UBSan over lib/scp03 response handling and the MODE_PCR TLV walk.
#   ./run_fuzz_scp03.sh [seconds]   (default 120)
cd "$(dirname "$0")"
SECS=${1:-120}
mkdir -p /tmp/fz_scp03 corpus_scp03
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
  -I../lib/scp03 -I../lib/aes128 fuzz_scp03.c ../lib/scp03/scp03.c ../lib/aes128/aes128.c -o /tmp/fz_scp03/fz || exit 1
/tmp/fz_scp03/fz corpus_scp03 -max_len=1200 -max_total_time=$SECS -print_final_stats=1 -use_value_profile=1 2>&1 | tail -25
