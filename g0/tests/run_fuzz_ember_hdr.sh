#!/bin/bash
# 28 Oct 2026: randomised block trees through the header clock under ASan + UBSan.
set -e
gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Isrc -Ilib/g0crypto \
  tests/fuzz_ember_hdr.c src/ember_hdr.c lib/g0crypto/sha256.c -o /tmp/g0_fuzz_ember_hdr
/tmp/g0_fuzz_ember_hdr "$@"
