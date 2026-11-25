/* ───────────────────────────────────────────────────────────────────────────
 * overlay_kat.c — known-answer tests for the XOR overlay construction.
 *
 *   cc -Wall -Wextra -fsanitize=address,undefined -o overlay_kat \
 *      overlay_kat.c -I../src -lmbedcrypto && ./overlay_kat
 *
 * Same shape as dice_kat.c and quad_kat.c. The vectors are PINNED: if a change
 * moves any of them, either the change is wrong or the published specification
 * just changed and every board produced by older firmware now derives a
 * different wallet.
 *
 * T5 is the one that matters most. The whole reason this construction uses XOR
 * rather than a hash is that a human can check it cell by cell on screen. If
 * the bit indexing in overlay_entropy.h ever disagrees with what the display
 * draws, the user's spot-check silently becomes meaningless — so the mapping is
 * pinned against an independent implementation, not just against itself.
 * ───────────────────────────────────────────────────────────────────────── */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "overlay_entropy.h"

static int fails = 0;

static void hx(const uint8_t *b, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = H[b[i] >> 4]; out[i*2+1] = H[b[i] & 15]; }
    out[n*2] = 0;
}
static void ck(const char *what, bool ok) {
    printf(ok ? "  ok   %s\n" : "  FAIL %s\n", what);
    if (!ok) fails++;
}
static void ckhex(const char *what, const uint8_t *b, const char *want) {
    char got[65]; hx(b, 32, got);
    if (!strcmp(got, want)) printf("  ok   %s\n", what);
    else { printf("  FAIL %s\n       got  %s\n       want %s\n", what, got, want); fails++; }
}

int main(void) {
    uint8_t A[32], B[32], board[32], out[32];
    for (int i = 0; i < 32; i++) { A[i] = (uint8_t)(0xA0 + i); B[i] = (uint8_t)(0x5A + i); }

    printf("T1  the mix\n");
    ovlXor(A, B, board);
    ckhex("board = A xor B", board,
          "fafafefefafac6c6cacacececacac6c6dadadededadac6c6cacacececacac6c6");
    ovlEntropyFromBoard(board, out);
    ckhex("entropy = sha256(board)", out,
          "331a8664d87ab2850804d2038e018361a70cdd42fc6e7b028f7b9802ca415238");

    printf("T2  XOR algebra the user relies on\n");
    {
        uint8_t t[32], u[32];
        ovlXor(B, A, t);
        ck("commutative — layer order cannot matter", !memcmp(t, board, 32));
        ovlXor(board, B, t);
        ck("board xor B recovers A", !memcmp(t, A, 32));
        ovlXor(board, A, t);
        ck("board xor A recovers B", !memcmp(t, B, 32));
        ovlXor(A, A, t);
        ck("a layer xored with itself is zero", ovlLayerConstant(t));
        memset(u, 0, sizeof u);
        ovlXor(A, u, t);
        ck("xor with a dead layer is a bijection", !memcmp(t, A, 32));
    }

    printf("T3  degenerate boards\n");
    {
        uint8_t z[32]; memset(z, 0, sizeof z);
        ovlEntropyFromBoard(z, out);
        ckhex("all-zero board", out,
              "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
        ck("all-zero is flagged constant", ovlLayerConstant(z));
        memset(z, 0xFF, sizeof z);
        ck("all-ones is flagged constant", ovlLayerConstant(z));
        z[7] = 0xFE;
        ck("one flipped bit is not constant", !ovlLayerConstant(z));
    }

    printf("T4  negative controls\n");
    {
        uint8_t A2[32], b2[32], h2[32];
        memcpy(A2, A, 32); A2[0] ^= 0x01;          /* one bit of one layer */
        ovlXor(A2, B, b2);
        ck("one flipped source bit changes the board", memcmp(b2, board, 32) != 0);
        ovlEntropyFromBoard(b2, h2);
        ck("...and changes the entropy", memcmp(h2, out, 32) != 0);
    }

    printf("T5  the mapping is what the screen draws\n");
    {
        /* Independent implementation: cell (r,c) is bit r*16+c, MSB-first. The
         * display walks cells in this order, so if these disagree the on-screen
         * spot-check is checking the wrong cells. */
        for (int r = 0; r < 16; r++) {
            for (int c = 0; c < 16; c++) {
                int i = r * 16 + c;
                int ref = (board[i >> 3] >> (7 - (i & 7))) & 1;
                if (ovlGet(board, i) != ref) { ck("cell mapping", false); goto done5; }
            }
        }
        ck("all 256 cells map row-major MSB-first", true);
done5:  ;
        /* And the arithmetic the footer prints must hold for every cell. */
        int bad = 0;
        for (int i = 0; i < 256; i++)
            if ((ovlGet(A, i) ^ ovlGet(B, i)) != ovlGet(board, i)) bad++;
        ck("SE xor CAM == board, all 256 cells", bad == 0);
    }

    printf("T6  set/get round trip\n");
    {
        uint8_t g[32]; memset(g, 0, sizeof g);
        int bad = 0;
        for (int i = 0; i < 256; i++) { ovlSet(g, i, 1); if (!ovlGet(g, i)) bad++; }
        for (int i = 0; i < 256; i++) { ovlSet(g, i, 0); if (ovlGet(g, i))  bad++; }
        ck("every cell sets and clears", bad == 0);
        ck("cleared grid is all zero", ovlLayerConstant(g));
    }

    printf("T7  hex rendering\n");
    {
        char h[65]; ovlHex(board, 32, h);
        ck("ovlHex matches the board",
           !strcmp(h, "fafafefefafac6c6cacacececacac6c6dadadededadac6c6cacacececacac6c6"));
        ck("nul terminated at 64", h[64] == 0);
    }

    printf(fails ? "\nFAILED (%d)\n" : "\nAll KATs passed\n", fails);
    return fails ? 1 : 0;
}
