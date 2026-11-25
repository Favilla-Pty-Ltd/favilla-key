#!/bin/bash
# 28 Oct 2026: Emberwill transaction builder vs embit + BIP-143. Run from the project root.
set -e
gcc -O1 -Wall -Wextra -Isrc -Ilib/g0crypto -Itests tests/host_ember_tx.c src/ember_tx.c lib/g0crypto/sha256.c lib/g0crypto/ripemd160.c -o /tmp/g0_ember_tx
/tmp/g0_ember_tx "$@"
