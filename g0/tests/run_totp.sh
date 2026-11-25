#!/bin/bash
# src/totp.c against the RFC vectors (ASan/UBSan), and its size on the G0 if
# the ARM compiler is installed (CI). Run from g0/.
set -e
gcc -O2 -Wall -Wextra -fsanitize=address,undefined -Isrc tests/host_totp.c src/totp.c -o /tmp/g0_totp
/tmp/g0_totp
T=$(ls -d ~/.platformio/packages/toolchain-gccarmnoneeabi*/bin 2>/dev/null | head -1)
if [ -n "$T" ]; then
  $T/arm-none-eabi-gcc -mcpu=cortex-m0plus -mthumb -Os -ffunction-sections -fdata-sections -Isrc -c src/totp.c -o /tmp/t.o
  echo "src/totp.c: $($T/arm-none-eabi-size /tmp/t.o | tail -1 | awk '{print $1+$2" bytes flash"}')"
fi
