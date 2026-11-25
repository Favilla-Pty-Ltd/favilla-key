#!/bin/sh
# Build the ESP32-side parser fuzzers (9u, 8 Nov 2026): libFuzzer + ASan + UBSan.
#   sh fuzz/build.sh            -> fuzz/out/<name>
# Run one:  fuzz/out/fuzz_ur fuzz/corpus/ur -max_total_time=600
set -e
cd "$(dirname "$0")"
OUT=out; mkdir -p "$OUT"
S="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -g -O1"
I="-Iinc -I../src"
CXX="${CXX:-clang++} -std=c++17 $S $I"
CC="${CC:-clang} -std=c11 $S $I"
$CXX fuzz_app_channel.cpp -lcrypto -o $OUT/fuzz_app_channel
$CXX fuzz_chan_key.cpp    -lcrypto -o $OUT/fuzz_chan_key
$CXX fuzz_api_decode.cpp           -o $OUT/fuzz_api_decode
$CXX fuzz_otpauth.cpp              -o $OUT/fuzz_otpauth
$CXX fuzz_login_qr.cpp             -o $OUT/fuzz_login_qr
$CXX fuzz_app_pair_qr.cpp          -o $OUT/fuzz_app_pair_qr
$CXX fuzz_event_id.cpp -I../lib/ArduinoJson/src -o $OUT/fuzz_event_id
$CXX fuzz_event_verify.cpp -I../lib/ArduinoJson/src -lmbedcrypto -o $OUT/fuzz_event_verify   # 22 Nov audit: nostrverify::eventOk on relay JSON
$CC  fuzz_psbt.c -lmbedcrypto      -o $OUT/fuzz_psbt   # 11df: psbt.h hashes the previous transaction
$CC  fuzz_quirc.c ../src/decode.c ../src/version_db.c -o $OUT/fuzz_quirc
$CXX fuzz_ur.cpp -lmbedcrypto -o $OUT/fuzz_ur
echo "built: $(ls $OUT | tr '\n' ' ')"
# CTAP: the host/ scaffold (its own Arduino and USB shims) and the real record store
CTAPF="${CXX:-clang++} -std=c++17 $S -DARDUINO_USB_CDC_ON_BOOT=1 -I../host/inc -I../src -I../host"
$CTAPF fuzz_ctap.cpp ../host/rk_host.cpp -lcrypto -o $OUT/fuzz_ctap
$CTAPF -DFZ_PKR fuzz_ctap.cpp ../host/rk_host.cpp -lcrypto -o $OUT/fuzz_ctap_pkr
$CTAPF fuzz_ctaphid.cpp ../host/rk_host.cpp -lcrypto -o $OUT/fuzz_ctaphid   # 22 Nov audit: 64-byte HID packets (framing) into CTAP2
echo "built CTAP: fuzz_ctap fuzz_ctap_pkr fuzz_ctaphid"
# 11t (10 Nov 2026): the vault restore path the phone now feeds (VAULT_PUT) and the password-health layer
VF="$CTAPF -DFAVILLA_PK_RESTORABLE=1 -I../lib/ArduinoJson/src"
$VF fuzz_vault_restore.cpp ../host/rk_host.cpp ../src/vault_backup.cpp -lcrypto -o $OUT/fuzz_vault_restore
$VF fuzz_rk_health.cpp ../host/rk_host.cpp -lcrypto -o $OUT/fuzz_rk_health
echo "built vault: fuzz_vault_restore fuzz_rk_health"
# 24 Nov 2026: the breach-check floor (a too-small bucket records no verdict) and `vault recheck`: a plain test, run it
${CXX:-clang++} -std=c++17 -fsanitize=address,undefined -g -O1 -DARDUINO_USB_CDC_ON_BOOT=1 -DFAVILLA_PK_RESTORABLE=1 -I../host/inc -I../src -I../host -I../lib/ArduinoJson/src ../host/health_floor_test.cpp ../host/rk_host.cpp -lcrypto -o $OUT/health_floor_test && $OUT/health_floor_test | tail -1
