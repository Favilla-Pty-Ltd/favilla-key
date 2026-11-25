#!/bin/bash
# 25 Nov 2026 (v24): the vault limit log in the key page. Run from the project root.
set -e
gcc -O1 -Wall -Itests/hal_stub -Isrc -Ilib/g0crypto tests/host_ks_lim.c src/key_store.c lib/g0crypto/sha256.c -o /tmp/g0_ks_lim
/tmp/g0_ks_lim
