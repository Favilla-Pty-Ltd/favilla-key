#!/bin/sh
# 23 Nov 2026 (#61): ecdh_ct equals ecdh_raw (host, harness/hostshim Arduino shim).
set -e
cd "$(dirname "$0")"
c++ -std=c++17 -O1 -w -I../hostshim -I../../src ecdh_ct_test.cpp -lmbedcrypto -o /tmp/ecdh_ct_test
/tmp/ecdh_ct_test
