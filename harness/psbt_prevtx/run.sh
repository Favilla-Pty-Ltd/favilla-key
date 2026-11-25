#!/bin/sh
# 23 Nov 2026 (#57): host test for the previous-transaction check in src/psbt.h.
set -e
cd "$(dirname "$0")"
python3 gen.py
cc -std=c11 -Wall -Wno-unused-function -Wno-deprecated-declarations -I../../src psbt_prevtx_test.c -lmbedcrypto -o /tmp/psbt_prevtx_test
/tmp/psbt_prevtx_test
