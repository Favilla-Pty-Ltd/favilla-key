/* BIP-39 word list, front-coded (G0 v16, 7 Nov 2026; was next/bip39_words_fc.c).
 * Drop-in for src/bip39_words.c: same bip39_mnemonic_from_entropy(), about
 * 11.5 KB smaller. bip39_word() is gone: a compressed list is read by walking
 * it, and a walk that stopped at the wanted word would take a time that
 * depends on the word, i.e. on the seed. So every call walks all 2048 words
 * once and copies each wanted word out with masks, never a branch on a secret
 * index. The work and the memory touched are the same for every seed. */
#include "bip39_words.h"
#include "sha256.h"
#include <string.h>
#include "bip39_fc_data.h"

/* 0xFF when a == b, else 0x00, with no branch. */
static uint8_t ct_eq16(uint16_t a, uint16_t b) {
    uint32_t x = (uint32_t)(a ^ b);
    return (uint8_t)(((x - 1u) >> 16) & 0xFFu);   /* x == 0 -> 0xFFFF... >> 16 = 0xFFFF; x in 1..0xFFFF -> 0 */
}

/* Walk the list once. For each word i, every one of the n wanted indices
 * takes the word's 9 bytes (letters, NUL padded) under a mask that is 0xFF
 * only where idx[k] == i. out[k] must be zeroed by the caller. */
static void bip39_fc_pick(const uint16_t *idx, int n, char out[][9]) {
    char cur[9] = {0};
    uint32_t bit = 0;
    for (uint16_t i = 0; i < 2048; i++) {
        uint32_t v = 0;
        for (int b = 0; b < 7; b++, bit++) v = (v << 1) | ((BIP39_FC[bit >> 3] >> (7 - (bit & 7))) & 1u);
        uint32_t pre = v >> 4, suf = v & 15u;
        for (uint32_t j = 0; j < suf; j++) {
            uint32_t c = 0;
            for (int b = 0; b < 5; b++, bit++) c = (c << 1) | ((BIP39_FC[bit >> 3] >> (7 - (bit & 7))) & 1u);
            cur[pre + j] = (char)('a' + c);
        }
        for (uint32_t j = pre + suf; j < 9; j++) cur[j] = 0;
        for (int k = 0; k < n; k++) {
            const uint8_t m = ct_eq16(idx[k], i);
            for (int j = 0; j < 9; j++) out[k][j] |= (char)(cur[j] & m);
        }
    }
    volatile char *vc = cur; for (int j = 0; j < 9; j++) vc[j] = 0;
}

int bip39_mnemonic_from_entropy(const uint8_t *ent, int wc, char *out, size_t cap) {
    int elen = (wc == 12) ? 16 : (wc == 24) ? 32 : 0;
    if (!elen || cap < 216) return -1;
    uint8_t h[32]; sha256(ent, (size_t)elen, h);
    uint8_t bits[33]; memcpy(bits, ent, (size_t)elen); bits[elen] = h[0];
    uint16_t idx[24]; char w[24][9];
    memset(w, 0, sizeof w);
    for (int k = 0; k < wc; k++) {
        uint16_t v = 0;
        for (int b = 0; b < 11; b++) { int bit = k * 11 + b; v = (uint16_t)((v << 1) | ((bits[bit >> 3] >> (7 - (bit & 7))) & 1)); }
        idx[k] = v;
    }
    bip39_fc_pick(idx, wc, w);
    size_t o = 0;
    for (int k = 0; k < wc; k++) {
        size_t l = strnlen(w[k], 9);
        if (o + l + 1 >= cap) { o = 0; break; }
        if (k) out[o++] = ' ';
        memcpy(out + o, w[k], l); o += l;
    }
    out[o] = 0;
    volatile uint8_t *vb = bits; for (size_t i = 0; i < sizeof(bits); i++) vb[i] = 0;
    volatile uint8_t *vh = h; for (size_t i = 0; i < sizeof(h); i++) vh[i] = 0;
    volatile uint16_t *vi = idx; for (int i = 0; i < 24; i++) vi[i] = 0;
    volatile char *vw = &w[0][0]; for (size_t i = 0; i < sizeof(w); i++) vw[i] = 0;
    return o ? (int)o : -1;
}
