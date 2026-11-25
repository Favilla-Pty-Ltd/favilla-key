// ─────────────────────────────────────────────────────────────────────────────
// overlay_entropy.h — the XOR overlay seed construction, PURE.  (Favilla KEY)
//
// Extracted from the UI (entropy_overlay.h) for the same reason dice_entropy.h
// and seed_entropy.h were: a construction that derives a wallet must be
// known-answer testable, and that needs a function with no globals, no I/O and
// no hardware. See harness/overlay_kat.c for the pinned vectors.
//
// THE PUBLISHED, VERIFIABLE SPECIFICATION
// ---------------------------------------
//     A       = SE051 grid    16 x 16 bits = 32 bytes, frozen by the user
//     B       = camera grid   16 x 16 bits = 32 bytes, frozen by the user
//     board   = A XOR B
//     entropy = SHA-256( board )
//     seed    = BIP-39( entropy[:len] )      len = 16 (12w) or 32 (24w)
//
//   - row-major, cell (r,c) is bit r*16 + c, packed MSB-first
//   - no domain tag, no device secret, nothing else mixed in
//
// External check, two lines on any airgapped machine:
//     python3 -c "a=bytes.fromhex('<A>');b=bytes.fromhex('<B>');print((int.from_bytes(a,'big')^int.from_bytes(b,'big')).to_bytes(32,'big').hex())"
//     printf '<board>' | xxd -r -p | sha256sum
//
// WHY XOR AND NOT A HASH OF THE TWO
// ---------------------------------
// A hash would combine them just as well cryptographically, but a human cannot
// check a hash by looking. XOR is the only mixing step a person can verify
// unaided: if the two source cells differ the board cell is lit, if they match
// it is dark. The device shows all three grids and the user can spot-check any
// cell on screen. That is the entire reason this construction exists.
//
// WHAT IT DEFENDS AGAINST, PRECISELY
// ----------------------------------
// The SE051 sits on I2C and never sees the camera frames; the camera never sees
// the SE051's output. Neither vendor can choose its contribution to cancel the
// other, so a backdoor in EITHER part alone leaves the board unpredictable to
// that vendor. This is real and it is the strongest claim in the design.
//
// It does NOT defend against the integrator. The ESP32 reads both layers and
// performs the XOR itself, so compromised firmware can simply pick
// B = A XOR target. Component diversity cannot reach that — reproducible builds
// and secure boot can. Do not let the marketing blur these two.
// ─────────────────────────────────────────────────────────────────────────────
#ifndef FAVILLA_OVERLAY_ENTROPY_H
#define FAVILLA_OVERLAY_ENTROPY_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#define OVL_N      16
#define OVL_CELLS  (OVL_N * OVL_N)      // 256
#define OVL_BYTES  (OVL_CELLS / 8)      // 32

// ── bit accessors: row-major, MSB-first. Must match the drawing code. ───────
static inline int ovlGet(const uint8_t* g, int i){
  return (g[i >> 3] >> (7 - (i & 7))) & 1;
}
static inline void ovlSet(uint8_t* g, int i, int v){
  uint8_t m = (uint8_t)(1u << (7 - (i & 7)));
  if(v) g[i >> 3] |= m; else g[i >> 3] = (uint8_t)(g[i >> 3] & ~m);
}

// ── the mix. board = A XOR B, cell by cell. ────────────────────────────────
static void ovlXor(const uint8_t a[OVL_BYTES], const uint8_t b[OVL_BYTES],
                   uint8_t out[OVL_BYTES]){
  for(int i = 0; i < OVL_BYTES; i++) out[i] = (uint8_t)(a[i] ^ b[i]);
}

// ── PURE. entropy = SHA-256(board). Nothing else. ──────────────────────────
static void ovlEntropyFromBoard(const uint8_t board[OVL_BYTES], uint8_t out[32]){
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, board, OVL_BYTES);
  mbedtls_sha256_finish(&sha, out);
  mbedtls_sha256_free(&sha);
}

// ── a layer that is all-zero or all-one contributes nothing ────────────────
// Not a randomness test — nothing computable here is. It only catches a source
// that has died in the most obvious way, which is the failure a health check
// CAN see. Weak sources pass this and every other test we could write.
static bool ovlLayerConstant(const uint8_t g[OVL_BYTES]){
  int allZero = 1, allOne = 1;
  for(int i = 0; i < OVL_BYTES; i++){
    if(g[i] != 0x00) allZero = 0;
    if(g[i] != 0xFF) allOne  = 0;
  }
  return allZero || allOne;
}

// ── 32 bytes -> 64 lowercase hex chars, for display / QR / transcription ───
static void ovlHex(const uint8_t* b, int n, char* out){
  static const char* H = "0123456789abcdef";
  for(int i = 0; i < n; i++){
    out[i * 2]     = H[(b[i] >> 4) & 0xF];
    out[i * 2 + 1] = H[b[i] & 0xF];
  }
  out[n * 2] = 0;
}

#endif // FAVILLA_OVERLAY_ENTROPY_H
