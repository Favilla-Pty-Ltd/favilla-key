#!/bin/bash
# The front-coded word list (next/bip39_words_fc.c) must give byte-identical
# mnemonics to the v15 one (tests/ref/bip39_words_v15.c). Run from g0/.
set -e
python3 tools/gen_bip39_fc.py
CF="-O2 -Wall -Wextra -Ilib/g0crypto -Isrc"
gcc $CF tests/host_bip39_fc.c tests/ref/bip39_words_v15.c lib/g0crypto/sha256.c -o /tmp/g0_bip39_old
gcc $CF -fsanitize=address,undefined tests/host_bip39_fc.c src/bip39_words.c lib/g0crypto/sha256.c -o /tmp/g0_bip39_new
/tmp/g0_bip39_old > /tmp/g0_bip39_old.txt
/tmp/g0_bip39_new > /tmp/g0_bip39_new.txt
N=$(wc -l < /tmp/g0_bip39_old.txt)
cmp /tmp/g0_bip39_old.txt /tmp/g0_bip39_new.txt && echo "PASS: $N mnemonics identical (every word in every position, random 12 and 24)"
tail -1 /tmp/g0_bip39_new.txt | grep -q END
# Size on the target, if the ARM compiler is installed (CI has it).
T=$(ls -d ~/.platformio/packages/toolchain-gccarmnoneeabi*/bin 2>/dev/null | head -1)
if [ -n "$T" ]; then
  for f in tests/ref/bip39_words_v15.c src/bip39_words.c; do
    $T/arm-none-eabi-gcc -mcpu=cortex-m0plus -mthumb -Os -ffunction-sections -fdata-sections -Ilib/g0crypto -Isrc -c $f -o /tmp/b.o
    echo "$f: $($T/arm-none-eabi-size /tmp/b.o | tail -1 | awk '{print $1+$2" bytes flash"}')"
  done
fi
