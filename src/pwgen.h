// =============================================================================
// pwgen.h - the KEY's password generator (3 Nov 2026, Vault spec 7f / 6).
// Pure code: the caller supplies 32 bytes of seed (SHA-256 of the SE TRNG and
// the ESP32 RNG, concatenated: a weak source cannot subtract), the host tests
// include this file as it is.
//
// Characters come from a stream SHA-256(seed || counter), one byte at a time,
// with rejection so every character of the alphabet is equally likely. A
// password must contain a lower-case letter, an upper-case letter, a digit and
// (when symbols are on) a symbol; one that does not is drawn again, which
// keeps the distribution uniform over the passwords that qualify.
//
// Policy word stored with the entry (RkPass.policy):
//   bits 0..7  length          bits 8..11 classes (1 lower, 2 upper, 4 digit, 8 symbol)
//   bits 16..23 symbol set (0 = kbd::kGenSymbols)   bit 24 version 1   bit 31 pending:
//   saved on the KEY with no real site yet (the PWA asks for site and username).
// =============================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "kbd_layout.h"
#include "mbedtls/sha256.h"

namespace pwgen {

constexpr uint32_t CL_LOWER = 1, CL_UPPER = 2, CL_DIGIT = 4, CL_SYMBOL = 8;
constexpr uint32_t POLICY_V1 = 1u << 24, POLICY_PENDING = 1u << 31;
constexpr int MAX_LEN = 64;
inline uint32_t policy(int len, uint32_t classes) { return (uint32_t)(len & 0xFF) | ((classes & 0xF) << 8) | POLICY_V1; }

struct Stream {
  uint8_t seed[32]; uint8_t block[32]; uint32_t ctr; int pos;
  void init(const uint8_t s[32]) { memcpy(seed, s, 32); ctr = 0; pos = 32; }
  uint8_t next() {
    if (pos == 32) {
      uint8_t m[36]; memcpy(m, seed, 32); m[32] = (uint8_t)(ctr >> 24); m[33] = (uint8_t)(ctr >> 16); m[34] = (uint8_t)(ctr >> 8); m[35] = (uint8_t)ctr; ctr++;
      mbedtls_sha256(m, sizeof m, block, 0);
      memset(m, 0, sizeof m); pos = 0;
    }
    return block[pos++];
  }
  void wipe() { volatile uint8_t* v = (volatile uint8_t*)this; for (size_t i = 0; i < sizeof *this; i++) v[i] = 0; }
};

inline size_t alphabet(uint32_t classes, char* out) {
  size_t n = 0;
  if (classes & CL_LOWER) for (char c = 'a'; c <= 'z'; c++) out[n++] = c;
  if (classes & CL_UPPER) for (char c = 'A'; c <= 'Z'; c++) out[n++] = c;
  if (classes & CL_DIGIT) for (char c = '0'; c <= '9'; c++) out[n++] = c;
  if (classes & CL_SYMBOL) for (const char* p = kbd::kGenSymbols; *p; p++) out[n++] = *p;
  out[n] = 0;
  return n;
}
inline uint32_t classesOf(const char* s, size_t n) {
  uint32_t c = 0;
  for (size_t i = 0; i < n; i++) {
    char x = s[i];
    if (x >= 'a' && x <= 'z') c |= CL_LOWER; else if (x >= 'A' && x <= 'Z') c |= CL_UPPER;
    else if (x >= '0' && x <= '9') c |= CL_DIGIT; else c |= CL_SYMBOL;
  }
  return c;
}
// Writes len characters and a NUL to out (len + 1 bytes). false on a bad
// length or class set (never on chance: 64 draws without every class needs a
// probability below 2^-100 at the lengths offered).
inline bool generate(const uint8_t seed[32], int len, uint32_t classes, char* out) {
  if (len < 8 || len > MAX_LEN || !(classes & (CL_LOWER | CL_UPPER | CL_DIGIT))) return false;
  char abc[100]; size_t an = alphabet(classes, abc);
  unsigned lim = (256u / an) * an;
  Stream st; st.init(seed);
  bool ok = false;
  for (int tries = 0; tries < 64 && !ok; tries++) {
    for (int i = 0; i < len; i++) { uint8_t b; do b = st.next(); while (b >= lim); out[i] = abc[b % an]; }
    out[len] = 0;
    ok = classesOf(out, len) == classes;
  }
  st.wipe();
  if (!ok) memset(out, 0, len + 1);
  return ok;
}

// 11bi (issue #38): a password to a site's rules, for iPhone AutoFill's GEN_PW.
// The alphabet is the allowed letter and digit classes plus specials (only when
// allowed has CL_SYMBOL; specials holds no letters or digits). Every required
// class appears, and no character appears more than twice in a row; a draw that
// breaks either rule is thrown away whole, which keeps the result uniform over
// the passwords that qualify. Writes len characters and a NUL. false on bad
// arguments, or when 256 draws all failed (only for rules that barely allow a
// password, never at the lengths and sets GEN_PW accepts in practice).
inline bool generateRules(const uint8_t seed[32], int len, uint32_t required, uint32_t allowed, const char* specials, char* out) {
  if (len < 8 || len > MAX_LEN || !(allowed & (CL_LOWER | CL_UPPER | CL_DIGIT)) || (required & ~allowed)) return false;
  char abc[160]; size_t an = 0;
  if (allowed & CL_LOWER) for (char c = 'a'; c <= 'z'; c++) abc[an++] = c;
  if (allowed & CL_UPPER) for (char c = 'A'; c <= 'Z'; c++) abc[an++] = c;
  if (allowed & CL_DIGIT) for (char c = '0'; c <= '9'; c++) abc[an++] = c;
  if (allowed & CL_SYMBOL) {
    if (!specials || !*specials) return false;
    for (const char* p = specials; *p && an < sizeof abc - 1; p++) abc[an++] = *p;
  }
  if (an < 2) return false;
  const unsigned lim = (256u / an) * an;
  Stream st; st.init(seed);
  bool ok = false;
  for (int tries = 0; tries < 256 && !ok; tries++) {
    for (int i = 0; i < len; i++) { uint8_t b; do b = st.next(); while (b >= lim); out[i] = abc[b % an]; }
    out[len] = 0;
    ok = (classesOf(out, len) & required) == required;
    for (int i = 2; ok && i < len; i++) if (out[i] == out[i - 1] && out[i] == out[i - 2]) ok = false;
  }
  st.wipe();
  if (!ok) memset(out, 0, len + 1);
  return ok;
}

}  // namespace pwgen
