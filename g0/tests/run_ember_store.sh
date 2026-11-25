#!/bin/bash
# 28 Oct 2026: Emberwill flash store with power cuts, under ASan + UBSan. Run from the project root.
set -e
gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -Isrc -Ilib/g0crypto \
  tests/host_ember_store.c src/ember_store.c src/ember_hdr.c lib/g0crypto/sha256.c -o /tmp/g0_ember_store
/tmp/g0_ember_store "$@"
