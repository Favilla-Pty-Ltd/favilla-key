// ─────────────────────────────────────────────────────────────────────────────
// quad_entropy.h — the quadrant-board seed construction, PURE.  (Favilla KEY)
//
// Extracted from the UI (entropy_quad.h) for the same reason dice_entropy.h and
// seed_entropy.h were: a construction that derives a wallet must be known-answer
// testable, and that requires a function with no globals, no I/O and no
// hardware. See harness/quad_kat.c for the pinned vectors.
//
// THE PUBLISHED, VERIFIABLE SPECIFICATION
// ---------------------------------------
//     board   = 16 x 16 bits = 256 cells = 32 bytes
//     entropy = SHA-256( board )                  // the 32 bytes, raw
//     seed    = BIP-39( entropy[:len] )           // len = 16 (12w) or 32 (24w)
//
//   - the board is exactly what is drawn on screen: row-major, cell (r,c) is
//     bit index r*16 + c, packed MSB-first into board[i>>3]
//   - four 8x8 quadrants, each filled by one source, each filled exactly once
//   - nothing else is mixed in — no domain tag, no device secret, no RNG
//
// NO domain tag is deliberate and load-bearing, exactly as in dice_entropy.h: a
// tag would break external reproducibility. The owner reads the 32 board bytes
// off the screen (or scans them) and checks on any airgapped machine:
//
//     printf '<64 hex chars>' | xxd -r -p | sha256sum
//
// and gets the same entropy. That is the whole point of this path: the picture
// IS the pre-image. If the displayed board does not hash to the displayed
// entropy, the device is lying, and anyone can check.
//
// WHAT THIS DOES NOT GIVE YOU
// ---------------------------
// 256 cells are not 256 bits. Verifiability says the device used the board you
// saw; it says nothing about how much unpredictability the sources put in it.
// The measured per-source figures live in entropy_quad.h and are shown on
// screen. See the entropy study, §3.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_QUAD_ENTROPY_H
#define FAVILLA_QUAD_ENTROPY_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#define QUAD_N       16                      // board is 16 x 16
#define QUAD_CELLS   (QUAD_N * QUAD_N)       // 256
#define QUAD_BYTES   (QUAD_CELLS / 8)        // 32
#define QUAD_SIDE    8                       // quadrant is 8 x 8
#define QUAD_BITS    (QUAD_SIDE * QUAD_SIDE) // 64 bits per quadrant
#define QUAD_BLKB    (QUAD_BITS / 8)         // 8 bytes per block
#define QUAD_COUNT   4                       // TL, TR, BL, BR
#define QUAD_ALL     0x0F                    // all four placed

// ── bit accessors: row-major, MSB-first. Must match the drawing code. ────────
static inline int quadGet(const uint8_t* b, int i){
  return (b[i >> 3] >> (7 - (i & 7))) & 1;
}
static inline void quadSet(uint8_t* b, int i, int v){
  uint8_t m = (uint8_t)(1u << (7 - (i & 7)));
  if(v) b[i >> 3] |= m; else b[i >> 3] = (uint8_t)(b[i >> 3] & ~m);
}

// Top-left cell of quadrant q. 0 = TL, 1 = TR, 2 = BL, 3 = BR.
static inline void quadOrigin(int q, int* r0, int* c0){
  *r0 = (q >> 1) * QUAD_SIDE;
  *c0 = (q & 1)  * QUAD_SIDE;
}

// ── place one 8x8 block into quadrant q ─────────────────────────────────────
// blk[r] is one row, bit 7 = leftmost column, so the block reads the same way
// it is drawn. `cov` is the coverage map: one bit per board cell, set as it is
// written. Returns false — WITHOUT writing anything — if any target cell is
// already covered. That is the collision refusal: a silent overlap would reuse
// source bits and leave the board looking full when it is not.
static bool quadPlaceBlock(uint8_t board[QUAD_BYTES], uint8_t cov[QUAD_BYTES],
                           int q, const uint8_t blk[QUAD_BLKB]){
  if(q < 0 || q >= QUAD_COUNT) return false;
  int r0, c0; quadOrigin(q, &r0, &c0);
  for(int r = 0; r < QUAD_SIDE; r++)
    for(int c = 0; c < QUAD_SIDE; c++)
      if(quadGet(cov, (r0 + r) * QUAD_N + (c0 + c))) return false;   // collision
  for(int r = 0; r < QUAD_SIDE; r++){
    for(int c = 0; c < QUAD_SIDE; c++){
      int i = (r0 + r) * QUAD_N + (c0 + c);
      quadSet(board, i, (blk[r] >> (7 - c)) & 1);
      quadSet(cov,   i, 1);
    }
  }
  return true;
}

// ── the coverage gate: every one of the 256 cells written exactly once ──────
// Gaps are the dangerous case: an untouched cell is an initialised zero, which
// is indistinguishable on screen and in the hash from a source bit that
// happened to be zero. Fail closed on anything but 256/256.
static bool quadCoverageFull(const uint8_t cov[QUAD_BYTES]){
  for(int i = 0; i < QUAD_BYTES; i++) if(cov[i] != 0xFF) return false;
  return true;
}
static int quadCoverageCount(const uint8_t cov[QUAD_BYTES]){
  int n = 0;
  for(int i = 0; i < QUAD_CELLS; i++) n += quadGet(cov, i);
  return n;
}

// ── PURE. entropy = SHA-256(board). Nothing else. ───────────────────────────
static void quadEntropyFromBoard(const uint8_t board[QUAD_BYTES], uint8_t out[32]){
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, board, QUAD_BYTES);
  mbedtls_sha256_finish(&sha, out);
  mbedtls_sha256_free(&sha);
}

// ── board -> 64 lowercase hex chars, for display / QR / transcription ────────
static void quadBoardHex(const uint8_t board[QUAD_BYTES], char out[QUAD_BYTES * 2 + 1]){
  static const char* H = "0123456789abcdef";
  for(int i = 0; i < QUAD_BYTES; i++){
    out[i * 2]     = H[(board[i] >> 4) & 0xF];
    out[i * 2 + 1] = H[board[i] & 0xF];
  }
  out[QUAD_BYTES * 2] = 0;
}

#endif // FAVILLA_QUAD_ENTROPY_H
