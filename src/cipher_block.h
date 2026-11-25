// =============================================================================
// cipher_block.h - CIPHER's daily board from a Bitcoin block (issue #39, stage 3)
//
// A CIPHER day is 144 blocks. Its board is seeded by the hash of the day's
// first block (height a multiple of 144), so every KEY plays the same board
// that day, and nobody can know it in advance.
//
// The KEY is given the block as text, from favillakey.io over Wi-Fi or from a
// QR code:  "<height>,<header hex>"   or   "FCD1:<height>:<header hex>"
// (header = the 80-byte block header, 160 hex characters).
//
// The KEY trusts none of it blindly. It checks, on its own:
//   - the header's proof of work: double SHA-256 of the header, read as a
//     little-endian number, is at or below the target its nBits encodes;
//   - a difficulty floor: that target is at or below 2^(256 - CG_POW_MIN_ZEROS),
//     so the hash has at least that many leading zero bits. Forging a header
//     that passes costs real mining at today's difficulty;
//   - the height is a multiple of 144;
//   - when the KEY's clock is set, the block's time is within the last
//     CG_BLOCK_MAX_AGE_S (not an old block replayed) and not in the future.
// The height itself is not proven by a header; the site's leaderboard checks
// that the hash in a shared run is the real block at that height.
//
// Pure code (mbedtls SHA-256 only): tests/cipher_block_test.cpp runs it as is.
// =============================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/sha256.h"

#ifndef CG_POW_MIN_ZEROS
#define CG_POW_MIN_ZEROS 76            // ~ difficulty 2^44 (1.7e13); mainnet has been far above this for years
#endif
#define CG_BLOCK_DAY      144u          // blocks per CIPHER day
#define CG_BLOCK_MAX_AGE_S (2L * 86400L) // a day's first block is at most ~1 day old while it is "today"

struct CgBlock {
  bool     valid;
  uint32_t height;
  uint32_t time;          // header nTime (unix seconds)
  uint8_t  header[80];
  uint8_t  hash[32];      // block hash, in the usual display order (big-endian, leading zeros first)
};

namespace cgblock {

inline int hexv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline void dsha(const uint8_t* in, size_t n, uint8_t out[32]) {
  uint8_t t[32];
  mbedtls_sha256(in, n, t, 0);
  mbedtls_sha256(t, 32, out, 0);
}

// Leading zero bits of a big-endian 256-bit number.
inline int leadingZeros(const uint8_t be[32]) {
  int z = 0;
  for (int i = 0; i < 32; i++) {
    if (be[i] == 0) { z += 8; continue; }
    uint8_t b = be[i];
    while (!(b & 0x80)) { z++; b <<= 1; }
    break;
  }
  return z;
}

// nBits -> 256-bit big-endian target. false on a negative or overflowing encoding.
inline bool bitsToTarget(uint32_t bits, uint8_t be[32]) {
  memset(be, 0, 32);
  const uint32_t exp = bits >> 24, mant = bits & 0x007FFFFF;
  if (bits & 0x00800000) return false;          // negative
  if (mant == 0) return true;                   // zero target: nothing passes
  if (exp > 32) return false;                   // overflow
  // value = mant * 256^(exp - 3); place the three mantissa bytes
  for (int k = 0; k < 3; k++) {
    int pos = (int)exp - 1 - k;                 // byte index counted from the least significant end
    if (pos < 0) continue;
    if (pos > 31) return false;
    uint8_t byte = (uint8_t)(mant >> (8 * (2 - k)));
    be[31 - pos] = byte;
  }
  return true;
}

// a <= b for big-endian 256-bit numbers
inline bool leq(const uint8_t a[32], const uint8_t b[32]) {
  for (int i = 0; i < 32; i++) { if (a[i] != b[i]) return a[i] < b[i]; }
  return true;
}

// Verify an 80-byte header: fills hash, time. minZeros: the difficulty floor.
inline bool checkHeader(const uint8_t hdr[80], int minZeros, uint8_t hashBE[32], uint32_t* timeOut) {
  uint8_t h[32];
  dsha(hdr, 80, h);
  for (int i = 0; i < 32; i++) hashBE[i] = h[31 - i];   // display order
  uint32_t bits = (uint32_t)hdr[72] | ((uint32_t)hdr[73] << 8) | ((uint32_t)hdr[74] << 16) | ((uint32_t)hdr[75] << 24);
  uint8_t target[32];
  if (!bitsToTarget(bits, target)) return false;
  if (leadingZeros(target) < minZeros) return false;    // the difficulty floor
  if (!leq(hashBE, target)) return false;               // the proof of work
  if (timeOut) *timeOut = (uint32_t)hdr[68] | ((uint32_t)hdr[69] << 8) | ((uint32_t)hdr[70] << 16) | ((uint32_t)hdr[71] << 24);
  return true;
}

// Parse "<height>,<160 hex>" or "FCD1:<height>:<160 hex>" (surrounding
// whitespace allowed) and verify it. nowUnix 0 = clock unknown (age not
// checked). Returns false and leaves out.valid false on anything wrong.
inline bool parse(const char* text, int64_t nowUnix, CgBlock& out, int minZeros = CG_POW_MIN_ZEROS) {
  memset(&out, 0, sizeof(out));
  if (!text) return false;
  while (*text == ' ' || *text == '\n' || *text == '\r' || *text == '\t') text++;
  if (!strncmp(text, "FCD1:", 5)) text += 5;
  char* end = nullptr;
  if (*text < '0' || *text > '9') return false;
  unsigned long h = strtoul(text, &end, 10);
  if (!end || (*end != ',' && *end != ':') || h == 0 || h > 100000000UL) return false;
  if (h % CG_BLOCK_DAY) return false;
  const char* hx = end + 1;
  uint8_t hdr[80];
  for (int i = 0; i < 80; i++) {
    int a = hexv(hx[2 * i]);
    if (a < 0) return false;            // also stops at the NUL: never reads past a short input
    int b = hexv(hx[2 * i + 1]);
    if (b < 0) return false;
    hdr[i] = (uint8_t)(a << 4 | b);
  }
  const char* rest = hx + 160;
  while (*rest == ' ' || *rest == '\n' || *rest == '\r' || *rest == '\t') rest++;
  if (*rest) return false;
  uint8_t hash[32]; uint32_t t = 0;
  if (!checkHeader(hdr, minZeros, hash, &t)) return false;
  if (nowUnix > 0) {                                 // the caller passes 0 when its clock is not set
    if ((int64_t)t > nowUnix + 7200) return false;                    // from the future (2 h, as consensus allows)
    if (nowUnix - (int64_t)t > CG_BLOCK_MAX_AGE_S) return false;      // an old block replayed
  }
  out.valid = true; out.height = (uint32_t)h; out.time = t;
  memcpy(out.header, hdr, 80); memcpy(out.hash, hash, 32);
  return true;
}

// The board seed: SHA-256("CIPHER-DAY-v1" || block hash), first four bytes.
inline uint32_t seed(const CgBlock& b) {
  uint8_t m[13 + 32], d[32];
  memcpy(m, "CIPHER-DAY-v1", 13); memcpy(m + 13, b.hash, 32);
  mbedtls_sha256(m, sizeof m, d, 0);
  uint32_t s = (uint32_t)d[0] << 24 | (uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | d[3];
  return s ? s : 1;
}

inline void hashHex(const CgBlock& b, char out[65]) {
  static const char* H = "0123456789abcdef";
  for (int i = 0; i < 32; i++) { out[2 * i] = H[b.hash[i] >> 4]; out[2 * i + 1] = H[b.hash[i] & 15]; }
  out[64] = 0;
}

}  // namespace cgblock
