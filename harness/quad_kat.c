/* ───────────────────────────────────────────────────────────────────────────
 * quad_kat.c — known-answer tests for the quadrant board construction.
 *
 *   cc -Wall -Wextra -fsanitize=address,undefined -o quad_kat quad_kat.c \
 *      -I../src -lmbedcrypto && ./quad_kat
 *
 * Same shape as dice_kat.c. The vectors below are PINNED: if a change to
 * quad_entropy.h moves any of them, either the change is wrong or the
 * published specification just changed and every board hashed by an older
 * firmware now derives a different wallet. There is no third possibility.
 *
 * What is actually at risk here is the MAPPING, not the hash. SHA-256 is not
 * going to break; the row/column packing that decides which screen cell is
 * which bit is exactly the kind of thing that can be silently transposed, and
 * a transposed board still hashes to something that looks fine. Then the user
 * transcribes what is on screen, hashes it themselves, gets a different
 * answer, and concludes the device is lying. Hence T4 and T5.
 * ───────────────────────────────────────────────────────────────────────── */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "quad_entropy.h"

static int fails = 0;

static void hex(const uint8_t *b, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = H[b[i] >> 4]; out[i*2+1] = H[b[i] & 15]; }
    out[n*2] = 0;
}

static void expect_hash(const char *what, const uint8_t board[32], const char *want) {
    uint8_t out[32]; char got[65];
    quadEntropyFromBoard(board, out);
    hex(out, 32, got);
    if (strcmp(got, want) == 0) { printf("  ok   %s\n", what); }
    else { printf("  FAIL %s\n       got  %s\n       want %s\n", what, got, want); fails++; }
}

static void expect_true(const char *what, bool cond) {
    if (cond) printf("  ok   %s\n", what);
    else { printf("  FAIL %s\n", what); fails++; }
}

int main(void) {
    uint8_t board[QUAD_BYTES], cov[QUAD_BYTES];
    uint8_t A[8], B[8], C[8], D[8];
    for (int i = 0; i < 8; i++) { A[i] = 0xA0 + i; B[i] = 0xB0 + i; C[i] = 0xC0 + i; D[i] = 0xD0 + i; }

    printf("T1  degenerate boards\n");
    memset(board, 0x00, sizeof board);
    expect_hash("all-zero board",
                board, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
    memset(board, 0xFF, sizeof board);
    expect_hash("all-ones board",
                board, "af9613760f72635fbdb44a5a0a63c39f12af30f950a6ee5c971be188e89c4051");

    printf("T2  four blocks, TL/TR/BL/BR\n");
    memset(board, 0, sizeof board); memset(cov, 0, sizeof cov);
    expect_true("place TL", quadPlaceBlock(board, cov, 0, A));
    expect_true("place TR", quadPlaceBlock(board, cov, 1, B));
    expect_true("place BL", quadPlaceBlock(board, cov, 2, C));
    expect_true("place BR", quadPlaceBlock(board, cov, 3, D));
    char bh[65]; hex(board, QUAD_BYTES, bh);
    expect_true("board bytes interleave A|B then C|D",
                strcmp(bh, "a0b0a1b1a2b2a3b3a4b4a5b5a6b6a7b7"
                           "c0d0c1d1c2d2c3d3c4d4c5d5c6d6c7d7") == 0);
    if (strcmp(bh, "a0b0a1b1a2b2a3b3a4b4a5b5a6b6a7b7c0d0c1d1c2d2c3d3c4d4c5d5c6d6c7d7"))
        printf("       got  %s\n", bh);
    expect_hash("board hash",
                board, "a28485458e2d071b2a0fe7d9031e19d1adf006569cdc374e6918490a5b7bc5bd");

    printf("T3  coverage gate\n");
    expect_true("256 / 256 after four blocks", quadCoverageCount(cov) == 256);
    expect_true("coverage reported full",       quadCoverageFull(cov));
    {
        uint8_t b2[QUAD_BYTES], c2[QUAD_BYTES];
        memset(b2, 0, sizeof b2); memset(c2, 0, sizeof c2);
        quadPlaceBlock(b2, c2, 0, A); quadPlaceBlock(b2, c2, 1, B); quadPlaceBlock(b2, c2, 2, C);
        expect_true("three blocks is NOT full",  !quadCoverageFull(c2));
        expect_true("three blocks counts 192",   quadCoverageCount(c2) == 192);
    }

    printf("T4  collision refusal\n");
    {
        uint8_t b3[QUAD_BYTES], c3[QUAD_BYTES], before[QUAD_BYTES];
        memset(b3, 0, sizeof b3); memset(c3, 0, sizeof c3);
        quadPlaceBlock(b3, c3, 0, A);
        memcpy(before, b3, sizeof b3);
        expect_true("second placement in TL refused", !quadPlaceBlock(b3, c3, 0, D));
        expect_true("refused placement wrote nothing", memcmp(before, b3, sizeof b3) == 0);
        expect_true("out-of-range quadrant refused",  !quadPlaceBlock(b3, c3, 4, D));
    }

    printf("T5  the mapping is what the screen draws\n");
    {
        /* Independent implementation of the same mapping: quadrant q's row r is
         * one whole board byte, because the board is 16 cells wide and the
         * quadrant is 8 wide and byte-aligned. If the bit-level loop in
         * quad_entropy.h ever disagrees with this, the picture and the
         * pre-image have come apart. */
        uint8_t b4[QUAD_BYTES], c4[QUAD_BYTES], fast[QUAD_BYTES];
        const uint8_t *blk[4] = { A, B, C, D };
        memset(b4, 0, sizeof b4); memset(c4, 0, sizeof c4); memset(fast, 0, sizeof fast);
        for (int q = 0; q < 4; q++) quadPlaceBlock(b4, c4, q, blk[q]);
        for (int q = 0; q < 4; q++) {
            int r0 = (q >> 1) * 8, c0 = (q & 1) * 8;
            for (int r = 0; r < 8; r++) fast[(r0 + r) * 2 + (c0 / 8)] = blk[q][r];
        }
        expect_true("bit loop == byte-aligned fast path", memcmp(b4, fast, sizeof b4) == 0);

        /* Cell (r,c) on screen is bit r*16+c. Spot-check a known cell: the
         * top-left cell of BR is bit 8*16+8 = 136, which is bit 7 of D[0]=0xD0
         * -> 1. */
        expect_true("cell (8,8) is the MSB of BR row 0", quadGet(b4, 8 * 16 + 8) == 1);
        expect_true("cell (0,0) is the MSB of TL row 0", quadGet(b4, 0) == 1);
    }

    printf("T6  negative controls\n");
    {
        uint8_t b5[QUAD_BYTES], c5[QUAD_BYTES];
        memset(b5, 0, sizeof b5); memset(c5, 0, sizeof c5);
        /* B and C swapped: same four blocks, different placement, different key. */
        quadPlaceBlock(b5, c5, 0, A); quadPlaceBlock(b5, c5, 1, C);
        quadPlaceBlock(b5, c5, 2, B); quadPlaceBlock(b5, c5, 3, D);
        expect_hash("swapping two quadrants changes the hash",
                    b5, "9dfa6c22d6b1e56483562758e684561328ff31f46f87c930a84fc2733d0eb867");
        uint8_t h1[32], h2[32];
        quadEntropyFromBoard(board, h1); quadEntropyFromBoard(b5, h2);
        expect_true("...and is not the canonical board", memcmp(h1, h2, 32) != 0);
    }

    printf("T7  hex rendering matches the bytes\n");
    {
        char h[QUAD_BYTES * 2 + 1];
        quadBoardHex(board, h);
        expect_true("quadBoardHex == board bytes", strcmp(h, bh) == 0);
        expect_true("nul terminated at 64", h[64] == 0);
    }

    printf(fails ? "\nFAILED (%d)\n" : "\nAll KATs passed\n", fails);
    return fails ? 1 : 0;
}
