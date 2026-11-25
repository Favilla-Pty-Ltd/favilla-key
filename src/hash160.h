#ifndef FAVILLA_HASH160_H
#define FAVILLA_HASH160_H

// HASH160 = RIPEMD160(SHA256(data))
//
// Used for BIP-32 fingerprints, P2WPKH witness programs, P2PKH addresses.
//
// SHA-256 is provided by mbedtls (always available in ESP32 Arduino core).
// RIPEMD160 is implemented inline below — ESP-IDF's mbedtls is often built
// without RIPEMD160 to save flash, so we ship our own. The implementation is
// the standard reference algorithm from Dobbertin/Bosselaers/Preneel's spec,
// ~250 lines of pure C, runs in microseconds on ESP32-S3.
//
// Test vectors verified:
//   ripemd160("")                   = 9c1185a5c5e9fc54612808977ee8f548b2258d31
//   ripemd160("abc")                = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
//   ripemd160("message digest")     = 5d0689ef49d2fae572b881b123a85ffa21595f36
// All match the published spec.

#include <stdint.h>
#include <string.h>
#include "mbedtls/sha256.h"

// ─── RIPEMD160 (inline reference implementation) ─────────────────────────

typedef struct {
  uint32_t total[2];      // total bytes processed
  uint32_t state[5];      // chaining state
  uint8_t  buffer[64];    // pending block
} favilla_ripemd160_ctx;

static inline uint32_t ripemd160_rol(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

// Nonlinear functions f, g, h, i, j (per spec)
#define RMD_F(x, y, z) ((x) ^ (y) ^ (z))
#define RMD_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RMD_H(x, y, z) (((x) | ~(y)) ^ (z))
#define RMD_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define RMD_J(x, y, z) ((x) ^ ((y) | ~(z)))

// One round step (left line and right line use the same macro,
// just with different f/K constants).
#define RMD_FF(a, b, c, d, e, x, s) { \
  a += RMD_F(b, c, d) + (x); \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_GG(a, b, c, d, e, x, s) { \
  a += RMD_G(b, c, d) + (x) + 0x5A827999UL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_HH(a, b, c, d, e, x, s) { \
  a += RMD_H(b, c, d) + (x) + 0x6ED9EBA1UL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_II(a, b, c, d, e, x, s) { \
  a += RMD_I(b, c, d) + (x) + 0x8F1BBCDCUL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_JJ(a, b, c, d, e, x, s) { \
  a += RMD_J(b, c, d) + (x) + 0xA953FD4EUL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_FFF(a, b, c, d, e, x, s) RMD_FF(a, b, c, d, e, x, s)
#define RMD_GGG(a, b, c, d, e, x, s) { \
  a += RMD_G(b, c, d) + (x) + 0x7A6D76E9UL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_HHH(a, b, c, d, e, x, s) { \
  a += RMD_H(b, c, d) + (x) + 0x6D703EF3UL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_III(a, b, c, d, e, x, s) { \
  a += RMD_I(b, c, d) + (x) + 0x5C4DD124UL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}
#define RMD_JJJ(a, b, c, d, e, x, s) { \
  a += RMD_J(b, c, d) + (x) + 0x50A28BE6UL; \
  a = ripemd160_rol(a, s) + (e); \
  c = ripemd160_rol(c, 10); \
}

static void favilla_ripemd160_process(favilla_ripemd160_ctx* ctx,
                                       const uint8_t data[64]) {
  uint32_t X[16];
  for (int i = 0; i < 16; i++) {
    X[i] = ((uint32_t)data[i*4 + 0])       |
           ((uint32_t)data[i*4 + 1] <<  8) |
           ((uint32_t)data[i*4 + 2] << 16) |
           ((uint32_t)data[i*4 + 3] << 24);
  }

  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2];
  uint32_t d = ctx->state[3], e = ctx->state[4];
  uint32_t aa = a, bb = b, cc = c, dd = d, ee = e;

  // Left line — round 1 (F)
  RMD_FF(a, b, c, d, e, X[ 0], 11);  RMD_FF(e, a, b, c, d, X[ 1], 14);
  RMD_FF(d, e, a, b, c, X[ 2], 15);  RMD_FF(c, d, e, a, b, X[ 3], 12);
  RMD_FF(b, c, d, e, a, X[ 4],  5);  RMD_FF(a, b, c, d, e, X[ 5],  8);
  RMD_FF(e, a, b, c, d, X[ 6],  7);  RMD_FF(d, e, a, b, c, X[ 7],  9);
  RMD_FF(c, d, e, a, b, X[ 8], 11);  RMD_FF(b, c, d, e, a, X[ 9], 13);
  RMD_FF(a, b, c, d, e, X[10], 14);  RMD_FF(e, a, b, c, d, X[11], 15);
  RMD_FF(d, e, a, b, c, X[12],  6);  RMD_FF(c, d, e, a, b, X[13],  7);
  RMD_FF(b, c, d, e, a, X[14],  9);  RMD_FF(a, b, c, d, e, X[15],  8);
  // Round 2 (G)
  RMD_GG(e, a, b, c, d, X[ 7],  7);  RMD_GG(d, e, a, b, c, X[ 4],  6);
  RMD_GG(c, d, e, a, b, X[13],  8);  RMD_GG(b, c, d, e, a, X[ 1], 13);
  RMD_GG(a, b, c, d, e, X[10], 11);  RMD_GG(e, a, b, c, d, X[ 6],  9);
  RMD_GG(d, e, a, b, c, X[15],  7);  RMD_GG(c, d, e, a, b, X[ 3], 15);
  RMD_GG(b, c, d, e, a, X[12],  7);  RMD_GG(a, b, c, d, e, X[ 0], 12);
  RMD_GG(e, a, b, c, d, X[ 9], 15);  RMD_GG(d, e, a, b, c, X[ 5],  9);
  RMD_GG(c, d, e, a, b, X[ 2], 11);  RMD_GG(b, c, d, e, a, X[14],  7);
  RMD_GG(a, b, c, d, e, X[11], 13);  RMD_GG(e, a, b, c, d, X[ 8], 12);
  // Round 3 (H)
  RMD_HH(d, e, a, b, c, X[ 3], 11);  RMD_HH(c, d, e, a, b, X[10], 13);
  RMD_HH(b, c, d, e, a, X[14],  6);  RMD_HH(a, b, c, d, e, X[ 4],  7);
  RMD_HH(e, a, b, c, d, X[ 9], 14);  RMD_HH(d, e, a, b, c, X[15],  9);
  RMD_HH(c, d, e, a, b, X[ 8], 13);  RMD_HH(b, c, d, e, a, X[ 1], 15);
  RMD_HH(a, b, c, d, e, X[ 2], 14);  RMD_HH(e, a, b, c, d, X[ 7],  8);
  RMD_HH(d, e, a, b, c, X[ 0], 13);  RMD_HH(c, d, e, a, b, X[ 6],  6);
  RMD_HH(b, c, d, e, a, X[13],  5);  RMD_HH(a, b, c, d, e, X[11], 12);
  RMD_HH(e, a, b, c, d, X[ 5],  7);  RMD_HH(d, e, a, b, c, X[12],  5);
  // Round 4 (I)
  RMD_II(c, d, e, a, b, X[ 1], 11);  RMD_II(b, c, d, e, a, X[ 9], 12);
  RMD_II(a, b, c, d, e, X[11], 14);  RMD_II(e, a, b, c, d, X[10], 15);
  RMD_II(d, e, a, b, c, X[ 0], 14);  RMD_II(c, d, e, a, b, X[ 8], 15);
  RMD_II(b, c, d, e, a, X[12],  9);  RMD_II(a, b, c, d, e, X[ 4],  8);
  RMD_II(e, a, b, c, d, X[13],  9);  RMD_II(d, e, a, b, c, X[ 3], 14);
  RMD_II(c, d, e, a, b, X[ 7],  5);  RMD_II(b, c, d, e, a, X[15],  6);
  RMD_II(a, b, c, d, e, X[14],  8);  RMD_II(e, a, b, c, d, X[ 5],  6);
  RMD_II(d, e, a, b, c, X[ 6],  5);  RMD_II(c, d, e, a, b, X[ 2], 12);
  // Round 5 (J)
  RMD_JJ(b, c, d, e, a, X[ 4],  9);  RMD_JJ(a, b, c, d, e, X[ 0], 15);
  RMD_JJ(e, a, b, c, d, X[ 5],  5);  RMD_JJ(d, e, a, b, c, X[ 9], 11);
  RMD_JJ(c, d, e, a, b, X[ 7],  6);  RMD_JJ(b, c, d, e, a, X[12],  8);
  RMD_JJ(a, b, c, d, e, X[ 2], 13);  RMD_JJ(e, a, b, c, d, X[10], 12);
  RMD_JJ(d, e, a, b, c, X[14],  5);  RMD_JJ(c, d, e, a, b, X[ 1], 12);
  RMD_JJ(b, c, d, e, a, X[ 3], 13);  RMD_JJ(a, b, c, d, e, X[ 8], 14);
  RMD_JJ(e, a, b, c, d, X[11], 11);  RMD_JJ(d, e, a, b, c, X[ 6],  8);
  RMD_JJ(c, d, e, a, b, X[15],  5);  RMD_JJ(b, c, d, e, a, X[13],  6);

  // Right line — round 1 (J')
  RMD_JJJ(aa, bb, cc, dd, ee, X[ 5],  8);  RMD_JJJ(ee, aa, bb, cc, dd, X[14],  9);
  RMD_JJJ(dd, ee, aa, bb, cc, X[ 7],  9);  RMD_JJJ(cc, dd, ee, aa, bb, X[ 0], 11);
  RMD_JJJ(bb, cc, dd, ee, aa, X[ 9], 13);  RMD_JJJ(aa, bb, cc, dd, ee, X[ 2], 15);
  RMD_JJJ(ee, aa, bb, cc, dd, X[11], 15);  RMD_JJJ(dd, ee, aa, bb, cc, X[ 4],  5);
  RMD_JJJ(cc, dd, ee, aa, bb, X[13],  7);  RMD_JJJ(bb, cc, dd, ee, aa, X[ 6],  7);
  RMD_JJJ(aa, bb, cc, dd, ee, X[15],  8);  RMD_JJJ(ee, aa, bb, cc, dd, X[ 8], 11);
  RMD_JJJ(dd, ee, aa, bb, cc, X[ 1], 14);  RMD_JJJ(cc, dd, ee, aa, bb, X[10], 14);
  RMD_JJJ(bb, cc, dd, ee, aa, X[ 3], 12);  RMD_JJJ(aa, bb, cc, dd, ee, X[12],  6);
  // Round 2 (I')
  RMD_III(ee, aa, bb, cc, dd, X[ 6],  9);  RMD_III(dd, ee, aa, bb, cc, X[11], 13);
  RMD_III(cc, dd, ee, aa, bb, X[ 3], 15);  RMD_III(bb, cc, dd, ee, aa, X[ 7],  7);
  RMD_III(aa, bb, cc, dd, ee, X[ 0], 12);  RMD_III(ee, aa, bb, cc, dd, X[13],  8);
  RMD_III(dd, ee, aa, bb, cc, X[ 5],  9);  RMD_III(cc, dd, ee, aa, bb, X[10], 11);
  RMD_III(bb, cc, dd, ee, aa, X[14],  7);  RMD_III(aa, bb, cc, dd, ee, X[15],  7);
  RMD_III(ee, aa, bb, cc, dd, X[ 8], 12);  RMD_III(dd, ee, aa, bb, cc, X[12],  7);
  RMD_III(cc, dd, ee, aa, bb, X[ 4],  6);  RMD_III(bb, cc, dd, ee, aa, X[ 9], 15);
  RMD_III(aa, bb, cc, dd, ee, X[ 1], 13);  RMD_III(ee, aa, bb, cc, dd, X[ 2], 11);
  // Round 3 (H')
  RMD_HHH(dd, ee, aa, bb, cc, X[15],  9);  RMD_HHH(cc, dd, ee, aa, bb, X[ 5],  7);
  RMD_HHH(bb, cc, dd, ee, aa, X[ 1], 15);  RMD_HHH(aa, bb, cc, dd, ee, X[ 3], 11);
  RMD_HHH(ee, aa, bb, cc, dd, X[ 7],  8);  RMD_HHH(dd, ee, aa, bb, cc, X[14],  6);
  RMD_HHH(cc, dd, ee, aa, bb, X[ 6],  6);  RMD_HHH(bb, cc, dd, ee, aa, X[ 9], 14);
  RMD_HHH(aa, bb, cc, dd, ee, X[11], 12);  RMD_HHH(ee, aa, bb, cc, dd, X[ 8], 13);
  RMD_HHH(dd, ee, aa, bb, cc, X[12],  5);  RMD_HHH(cc, dd, ee, aa, bb, X[ 2], 14);
  RMD_HHH(bb, cc, dd, ee, aa, X[10], 13);  RMD_HHH(aa, bb, cc, dd, ee, X[ 0], 13);
  RMD_HHH(ee, aa, bb, cc, dd, X[ 4],  7);  RMD_HHH(dd, ee, aa, bb, cc, X[13],  5);
  // Round 4 (G')
  RMD_GGG(cc, dd, ee, aa, bb, X[ 8], 15);  RMD_GGG(bb, cc, dd, ee, aa, X[ 6],  5);
  RMD_GGG(aa, bb, cc, dd, ee, X[ 4],  8);  RMD_GGG(ee, aa, bb, cc, dd, X[ 1], 11);
  RMD_GGG(dd, ee, aa, bb, cc, X[ 3], 14);  RMD_GGG(cc, dd, ee, aa, bb, X[11], 14);
  RMD_GGG(bb, cc, dd, ee, aa, X[15],  6);  RMD_GGG(aa, bb, cc, dd, ee, X[ 0], 14);
  RMD_GGG(ee, aa, bb, cc, dd, X[ 5],  6);  RMD_GGG(dd, ee, aa, bb, cc, X[12],  9);
  RMD_GGG(cc, dd, ee, aa, bb, X[ 2], 12);  RMD_GGG(bb, cc, dd, ee, aa, X[13],  9);
  RMD_GGG(aa, bb, cc, dd, ee, X[ 9], 12);  RMD_GGG(ee, aa, bb, cc, dd, X[ 7],  5);
  RMD_GGG(dd, ee, aa, bb, cc, X[10], 15);  RMD_GGG(cc, dd, ee, aa, bb, X[14],  8);
  // Round 5 (F')  — note: F is symmetric so RMD_FFF == RMD_FF
  RMD_FFF(bb, cc, dd, ee, aa, X[12],  8);  RMD_FFF(aa, bb, cc, dd, ee, X[15],  5);
  RMD_FFF(ee, aa, bb, cc, dd, X[10], 12);  RMD_FFF(dd, ee, aa, bb, cc, X[ 4],  9);
  RMD_FFF(cc, dd, ee, aa, bb, X[ 1], 12);  RMD_FFF(bb, cc, dd, ee, aa, X[ 5],  5);
  RMD_FFF(aa, bb, cc, dd, ee, X[ 8], 14);  RMD_FFF(ee, aa, bb, cc, dd, X[ 7],  6);
  RMD_FFF(dd, ee, aa, bb, cc, X[ 6],  8);  RMD_FFF(cc, dd, ee, aa, bb, X[ 2], 13);
  RMD_FFF(bb, cc, dd, ee, aa, X[13],  6);  RMD_FFF(aa, bb, cc, dd, ee, X[14],  5);
  RMD_FFF(ee, aa, bb, cc, dd, X[ 0], 15);  RMD_FFF(dd, ee, aa, bb, cc, X[ 3], 13);
  RMD_FFF(cc, dd, ee, aa, bb, X[ 9], 11);  RMD_FFF(bb, cc, dd, ee, aa, X[11], 11);

  // Combine
  uint32_t t = ctx->state[1] + c + dd;
  ctx->state[1] = ctx->state[2] + d + ee;
  ctx->state[2] = ctx->state[3] + e + aa;
  ctx->state[3] = ctx->state[4] + a + bb;
  ctx->state[4] = ctx->state[0] + b + cc;
  ctx->state[0] = t;
}

static void favilla_ripemd160_init(favilla_ripemd160_ctx* ctx) {
  ctx->total[0] = 0;
  ctx->total[1] = 0;
  ctx->state[0] = 0x67452301UL;
  ctx->state[1] = 0xEFCDAB89UL;
  ctx->state[2] = 0x98BADCFEUL;
  ctx->state[3] = 0x10325476UL;
  ctx->state[4] = 0xC3D2E1F0UL;
}

static void favilla_ripemd160_update(favilla_ripemd160_ctx* ctx,
                                      const uint8_t* data, size_t len) {
  if (len == 0) return;
  uint32_t left = ctx->total[0] & 0x3F;
  uint32_t fill = 64 - left;

  ctx->total[0] += (uint32_t)len;
  if (ctx->total[0] < (uint32_t)len) ctx->total[1]++;

  if (left && len >= fill) {
    memcpy(ctx->buffer + left, data, fill);
    favilla_ripemd160_process(ctx, ctx->buffer);
    data += fill;
    len -= fill;
    left = 0;
  }
  while (len >= 64) {
    favilla_ripemd160_process(ctx, data);
    data += 64;
    len -= 64;
  }
  if (len > 0) {
    memcpy(ctx->buffer + left, data, len);
  }
}

static void favilla_ripemd160_finish(favilla_ripemd160_ctx* ctx, uint8_t out[20]) {
  // Append 0x80, pad to 56 mod 64, then 8-byte LE length.
  static const uint8_t padding[64] = { 0x80 };

  uint32_t last = ctx->total[0] & 0x3F;
  uint32_t padn = (last < 56) ? (56 - last) : (120 - last);

  uint8_t msglen[8];
  uint32_t high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
  uint32_t low  = (ctx->total[0] <<  3);
  msglen[0] = low         & 0xFF;
  msglen[1] = (low  >>  8) & 0xFF;
  msglen[2] = (low  >> 16) & 0xFF;
  msglen[3] = (low  >> 24) & 0xFF;
  msglen[4] = high         & 0xFF;
  msglen[5] = (high >>  8) & 0xFF;
  msglen[6] = (high >> 16) & 0xFF;
  msglen[7] = (high >> 24) & 0xFF;

  favilla_ripemd160_update(ctx, padding, padn);
  favilla_ripemd160_update(ctx, msglen, 8);

  for (int i = 0; i < 5; i++) {
    out[i*4 + 0] =  ctx->state[i]        & 0xFF;
    out[i*4 + 1] = (ctx->state[i] >>  8) & 0xFF;
    out[i*4 + 2] = (ctx->state[i] >> 16) & 0xFF;
    out[i*4 + 3] = (ctx->state[i] >> 24) & 0xFF;
  }
}

#undef RMD_F
#undef RMD_G
#undef RMD_H
#undef RMD_I
#undef RMD_J
#undef RMD_FF
#undef RMD_GG
#undef RMD_HH
#undef RMD_II
#undef RMD_JJ
#undef RMD_FFF
#undef RMD_GGG
#undef RMD_HHH
#undef RMD_III
#undef RMD_JJJ

// ─── HASH160 = RIPEMD160(SHA256(x)) ──────────────────────────────────────

static void hash160(const uint8_t* data, size_t data_len, uint8_t out[20]) {
  uint8_t sha[32];

  mbedtls_sha256_context sctx;
  mbedtls_sha256_init(&sctx);
  mbedtls_sha256_starts(&sctx, 0);
  mbedtls_sha256_update(&sctx, data, data_len);
  mbedtls_sha256_finish(&sctx, sha);
  mbedtls_sha256_free(&sctx);

  favilla_ripemd160_ctx rctx;
  favilla_ripemd160_init(&rctx);
  favilla_ripemd160_update(&rctx, sha, 32);
  favilla_ripemd160_finish(&rctx, out);
}

#endif // FAVILLA_HASH160_H
