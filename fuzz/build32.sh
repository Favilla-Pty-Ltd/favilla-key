#!/bin/sh
# 32-bit builds of the ESP32 parser fuzzers (audit 24 Nov 2026, issue #67).
# The ESP32-S3 has a 32-bit size_t, so a check like `pos + n > len` can wrap
# there and never on a 64-bit host. These builds use -m32 to get the same
# size_t, with libFuzzer + ASan + UBSan as in build.sh.
#   MBEDTLS32=/path/to/mbedtls-built-with-m32 sh fuzz/build32.sh   -> fuzz/out/<name>32
# MBEDTLS32 is an mbedTLS source tree built for i386, for example:
#   cmake -B b -DCMAKE_C_FLAGS=-m32 -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF && cmake --build b
# (then MBEDTLS32 points at a tree with include/ and library/libmbedcrypto.a).
# Run one the same way as the 64-bit builds:
#   fuzz/out/fuzz_psbt32 fuzz/corpus/psbt -max_total_time=600
set -e
cd "$(dirname "$0")"
: "${MBEDTLS32:?set MBEDTLS32 to an i386 mbedTLS tree (include/ and library/libmbedcrypto.a)}"
OUT=out; mkdir -p "$OUT"
S="-m32 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -g -O1"
I="-Iinc -I../src -I$MBEDTLS32/include"
L="$MBEDTLS32/library/libmbedcrypto.a"
CXX="${CXX:-clang++} -std=c++17 $S $I"
CC="${CC:-clang} -std=c11 $S $I"
$CC  fuzz_psbt.c $L                -o $OUT/fuzz_psbt32
$CXX fuzz_ur.cpp $L                -o $OUT/fuzz_ur32
$CXX fuzz_api_decode.cpp           -o $OUT/fuzz_api_decode32
$CXX fuzz_otpauth.cpp              -o $OUT/fuzz_otpauth32
$CXX fuzz_login_qr.cpp             -o $OUT/fuzz_login_qr32
$CXX fuzz_app_pair_qr.cpp          -o $OUT/fuzz_app_pair_qr32
$CXX fuzz_event_id.cpp -I../lib/ArduinoJson/src -o $OUT/fuzz_event_id32
$CXX fuzz_event_verify.cpp -I../lib/ArduinoJson/src $L -o $OUT/fuzz_event_verify32
$CC  fuzz_quirc.c ../src/decode.c ../src/version_db.c -o $OUT/fuzz_quirc32
echo "built (32-bit): $(ls $OUT | grep '32$' | tr '\n' ' ')"
