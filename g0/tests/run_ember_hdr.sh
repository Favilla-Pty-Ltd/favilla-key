#!/bin/bash
# 28 Oct 2026: Emberwill header clock + Merkle check on the host. Run from the project root.
set -e
gcc -O1 -Wall -Wextra -Isrc -Ilib/g0crypto -Itests \
  tests/host_ember_hdr.c src/ember_hdr.c lib/g0crypto/sha256.c -o /tmp/g0_ember_hdr
/tmp/g0_ember_hdr "$@"
