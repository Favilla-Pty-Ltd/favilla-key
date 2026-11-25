// =============================================================================
// antiexfil_host.h — the ESP32 (host) side of anti-exfil signing. 27 Oct 2026.
// =============================================================================
//
// Every signature the G0 makes is now two round trips (see g0 antiexfil.h):
//   1. host draws t (32 B), sends h = TAGGED_DATA(t) with the message
//   2. G0 answers R0 = k0*G, its nonce commitment
//   3. host reveals t
//   4. G0 answers the signature made with k = k0 + TAGGED_POINT(R0 || t)
//   5. host checks  x(R0 + TAGGED_POINT(R0 || t) * G) == r   <- THIS FILE
//      then verifies the signature as usual                  <- THIS FILE
//
// Step 5 is what makes the property real: a G0 that chose its final nonce by
// itself (to leak key bits through public signatures) cannot satisfy it,
// because it committed to R0 before it knew t. A host that skips this check
// gets nothing from the protocol, so the check is unconditional in a ship
// build. FAVILLA_BENCH_ANTIEXFIL_SKIP exists ONLY to demonstrate, on the
// bench, that a deliberately leaky G0 is accepted without the check and
// refused with it (acceptance test 4); it is stripped before a unit leaves
// the bench, like RCE_SIM was.
//
// Tags: ECDSA (BIP-143 inputs, BIP-137 messages) uses libsecp256k1-zkp's
// ecdsa_s2c tags "s2c/ecdsa/data" / "s2c/ecdsa/point"; BIP-340 (Nostr) uses
// the upstream Schnorr sign-to-contract proposal's "s2c/schnorr/data" /
// "s2c/schnorr/point". TAGGED(x) is the BIP-340 tagged hash
// SHA256(SHA256(tag) || SHA256(tag) || x). Must match g0 antiexfil.c byte for
// byte; the fixed-t KATs in both trees pin it.
//
// This header is included from g0_signer.cpp AFTER secp256k1.h and uses only
// its field / scalar / point primitives and tagged_hash(). It adds the two
// verifiers the ESP32 did not have before 27 Oct 2026: a full BIP-340
// verify and an ECDSA verify on (r, s), both needed because until now the
// ESP32 trusted the G0's signatures (the Bitcoin path compared only the
// pubkey and the sighash).
// =============================================================================
#pragma once

enum : uint8_t { AE_KIND_SCHNORR = 1, AE_KIND_ECDSA = 2, AE_KIND_ECDSA_RC = 3 };

static inline const char* ae_tag_data(uint8_t kind)  { return kind == AE_KIND_SCHNORR ? "s2c/schnorr/data"  : "s2c/ecdsa/data"; }
static inline const char* ae_tag_point(uint8_t kind) { return kind == AE_KIND_SCHNORR ? "s2c/schnorr/point" : "s2c/ecdsa/point"; }

// h = TAGGED_DATA(t)
static void ae_host_commit(uint8_t kind, const uint8_t t[32], uint8_t h[32]) {
  tagged_hash(ae_tag_data(kind), t, 32, h);
}

// Scalar inverse mod n by Fermat (n-2 ladder), as ecdsa_sign() does for k.
static void sc_inv_fermat(sc *r, const sc *a) {
  sc nm2; nm2.n[0] = SC_N[0] - 2; nm2.n[1] = SC_N[1]; nm2.n[2] = SC_N[2]; nm2.n[3] = SC_N[3];
  sc acc; acc.n[0] = 1; acc.n[1] = 0; acc.n[2] = 0; acc.n[3] = 0;
  sc base = *a;
  for (int i = 0; i < 256; i++) {
    if ((nm2.n[i / 64] >> (i % 64)) & 1ULL) { sc t; sc_mul(&t, &acc, &base); acc = t; }
    sc t; sc_mul(&t, &base, &base); base = t;
  }
  *r = acc;
}

// Is a field element (given as 32 big-endian bytes) < p ?
static bool fe_b32_lt_p(const uint8_t b[32]) {
  static const uint8_t P[32] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F };
  return memcmp(b, P, 32) < 0;
}
static bool sc_b32_lt_n(const uint8_t b[32]) {
  static const uint8_t N[32] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                                 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
  return memcmp(b, N, 32) < 0;
}

// Lift x to a curve point with the requested y parity (0 even, 1 odd).
// Rejects x >= p and x not on the curve (y^2 must equal x^3 + 7).
static bool pt_lift_x(Pt *P, const uint8_t x32[32], int want_odd) {
  if (!fe_b32_lt_p(x32)) return false;
  fe x; fe_from_b32(&x, x32);
  fe x3, y2, seven = {0}; seven.n[0] = 7;
  fe_sqr(&x3, &x); fe_mul(&x3, &x3, &x); fe_add(&y2, &x3, &seven);
  fe y; fe_sqrt(&y, &y2);
  fe chk; fe_sqr(&chk, &y); fe_norm(&chk); fe_norm(&y2);
  if (fe_cmp_raw(chk.n, y2.n) != 0) return false;          // not a quadratic residue: off the curve
  if (fe_is_odd(&y) != want_odd) fe_negate(&y, &y);
  P->x = x; P->y = y; P->inf = 0;
  return true;
}
static bool pt_from_compressed(Pt *P, const uint8_t c33[33]) {
  if (c33[0] != 0x02 && c33[0] != 0x03) return false;
  return pt_lift_x(P, c33 + 1, c33[0] == 0x03);
}

// The anti-exfil relation: x(R0 + TAGGED_POINT(R0 || t) * G) == r32.
// For BIP-340 r32 is sig[0..32] (a field element); for ECDSA it is r, which
// is x mod n (x >= n has probability ~2^-128; one subtraction covers it).
static bool ae_host_check(uint8_t kind, const uint8_t r0_33[33], const uint8_t t[32], const uint8_t r32[32]) {
  Pt R0; if (!pt_from_compressed(&R0, r0_33)) return false;
  uint8_t buf[65]; memcpy(buf, r0_33, 33); memcpy(buf + 33, t, 32);
  uint8_t eb[32]; tagged_hash(ae_tag_point(kind), buf, 65, eb);
  sc e; sc_from_b32(&e, eb); sc_reduce_once(&e);
  if (sc_is_zero(&e)) return false;
  JPt Ej; pt_mul_base(&Ej, &e);                         // e*G
  JPt Sj; jpt_madd(&Sj, &Ej, &R0);                      // + R0
  if (Sj.inf) return false;
  Pt S; jpt_to_affine(&S, &Sj); fe_norm(&S.x);
  uint8_t x[32]; fe_to_b32(x, &S.x);
  if (kind != AE_KIND_SCHNORR) {
    // r = x mod n
    sc xs; sc_from_b32(&xs, x); sc_reduce_once(&xs); sc_to_b32(x, &xs);
  }
  return memcmp(x, r32, 32) == 0;
}

// Full BIP-340 verification of sig64 over msg32 for the x-only pubkey pub32.
static bool schnorr_verify(const uint8_t pub32[32], const uint8_t msg32[32], const uint8_t sig64[64]) {
  Pt P; if (!pt_lift_x(&P, pub32, 0)) return false;              // even-Y point for the x-only key
  if (!fe_b32_lt_p(sig64)) return false;                          // r < p
  if (!sc_b32_lt_n(sig64 + 32)) return false;                     // s < n
  sc s; sc_from_b32(&s, sig64 + 32);
  uint8_t ch[96]; memcpy(ch, sig64, 32); memcpy(ch + 32, pub32, 32); memcpy(ch + 64, msg32, 32);
  uint8_t eb[32]; tagged_hash("BIP0340/challenge", ch, 96, eb);
  sc e; sc_from_b32(&e, eb); sc_reduce_once(&e);
  sc ne; sc_negate(&ne, &e);                                      // R = s*G - e*P
  JPt Rj; pt_mul_base(&Rj, &s);
  JPt Qj; pt_mul_pt(&Qj, &ne, &P);
  if (Qj.inf) return false;
  Pt Q; jpt_to_affine(&Q, &Qj);
  JPt Sum; jpt_madd(&Sum, &Rj, &Q);
  if (Sum.inf) return false;
  Pt R; jpt_to_affine(&R, &Sum);
  if (fe_is_odd(&R.y)) return false;
  fe_norm(&R.x); uint8_t rx[32]; fe_to_b32(rx, &R.x);
  return memcmp(rx, sig64, 32) == 0;
}

// ECDSA verification on (r, s) (both 32-byte big-endian, s may be high or
// low) for a compressed pubkey. Standard: u1 = z/s, u2 = r/s, x(u1*G + u2*Q) mod n == r.
static bool ecdsa_verify_rs(const uint8_t pub33[33], const uint8_t msg32[32], const uint8_t r32[32], const uint8_t s32[32]) {
  Pt Q; if (!pt_from_compressed(&Q, pub33)) return false;
  if (!sc_b32_lt_n(r32) || !sc_b32_lt_n(s32)) return false;
  sc r, s, z; sc_from_b32(&r, r32); sc_from_b32(&s, s32); sc_from_b32(&z, msg32); sc_reduce_once(&z);
  if (sc_is_zero(&r) || sc_is_zero(&s)) return false;
  sc w; sc_inv_fermat(&w, &s);
  sc u1, u2; sc_mul(&u1, &z, &w); sc_mul(&u2, &r, &w);
  JPt Aj; pt_mul_base(&Aj, &u1);
  JPt Bj; pt_mul_pt(&Bj, &u2, &Q);
  JPt Sum;
  if (Bj.inf) Sum = Aj;
  else { Pt B; jpt_to_affine(&B, &Bj); jpt_madd(&Sum, &Aj, &B); }
  if (Sum.inf) return false;
  Pt R; jpt_to_affine(&R, &Sum); fe_norm(&R.x);
  uint8_t x[32]; fe_to_b32(x, &R.x);
  sc xs; sc_from_b32(&xs, x); sc_reduce_once(&xs); sc_to_b32(x, &xs);
  return memcmp(x, r32, 32) == 0;
}

// DER (as the G0 returns it, strict low-S from libsecp256k1) -> r, s.
static bool der_to_rs(const uint8_t* der, size_t len, uint8_t r32[32], uint8_t s32[32]) {
  if (len < 8 || der[0] != 0x30 || der[1] != len - 2) return false;
  size_t p = 2;
  for (int i = 0; i < 2; i++) {
    if (p + 2 > len || der[p] != 0x02) return false;
    size_t l = der[p + 1]; p += 2;
    if (l == 0 || l > 33 || p + l > len) return false;
    const uint8_t* v = der + p; size_t vl = l;
    if (vl == 33) { if (v[0] != 0x00) return false; v++; vl--; }
    uint8_t* out = i == 0 ? r32 : s32;
    memset(out, 0, 32); memcpy(out + (32 - vl), v, vl);
    p += l;
  }
  return p == len;
}
