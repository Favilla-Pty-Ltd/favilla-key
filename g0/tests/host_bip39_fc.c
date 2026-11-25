/* Host test for next/bip39_words_fc.c (6 Nov 2026). Built twice, once with the
 * audited src/bip39_words.c and once with the front-coded one; run_bip39_fc.sh
 * diffs the two outputs, which must be byte-identical. Covers every one of the
 * 2048 words in every one of the 24 positions, plus random 12- and 24-word
 * entropies. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bip39_words.h"
static uint64_t s = 0x9E3779B97F4A7C15ull;
static uint8_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint8_t)s; }
static void set11(uint8_t *e, int pos, uint16_t v) {   /* word index v at word position pos */
    for (int b = 0; b < 11; b++) { int bit = pos * 11 + b, on = (v >> (10 - b)) & 1;
        if (bit >= 256) return;   /* the last word's low bits are the checksum */
        if (on) e[bit >> 3] |= (uint8_t)(0x80 >> (bit & 7)); else e[bit >> 3] &= (uint8_t)~(0x80 >> (bit & 7)); }
}
int main(void) {
    char out[216]; uint8_t e[32];
    for (int pos = 0; pos < 23; pos++)
        for (int v = 0; v < 2048; v++) {
            for (int i = 0; i < 32; i++) e[i] = rnd();
            set11(e, pos, (uint16_t)v);
            if (bip39_mnemonic_from_entropy(e, 24, out, sizeof out) < 0) { puts("ERR24"); return 1; }
            puts(out);
        }
    for (int t = 0; t < 4096; t++) {
        for (int i = 0; i < 32; i++) e[i] = rnd();
        if (bip39_mnemonic_from_entropy(e, (t & 1) ? 12 : 24, out, sizeof out) < 0) { puts("ERR"); return 1; }
        puts(out);
    }
    if (bip39_mnemonic_from_entropy(e, 18, out, sizeof out) != -1) { puts("ERR wc"); return 1; }
    if (bip39_mnemonic_from_entropy(e, 24, out, 100) != -1) { puts("ERR cap"); return 1; }
    puts("END");
    return 0;
}
