#ifndef FAVILLA_BIP32_H
#define FAVILLA_BIP32_H

// BIP32 hierarchical deterministic key derivation for Favilla Key
//
// Generalised BIP32 layer used by both NIP-06 (Nostr) and BIP-84 (Bitcoin).
// Supports both hardened (index >= 0x80000000) and non-hardened steps.

#include "mbed_secret.h"   // 2 Nov 2026: secret mbedTLS work stays on-chip
#include <stdint.h>
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/bignum.h"
#include "secp256k1.h"

// Sanity check: secp256k1.h must have defined these types. If you see
// a compile error pointing at the line below, secp256k1.h was not found
// or did not compile — check that it's in the sketch folder and the
// #include path resolves.
typedef sc  _favilla_bip32_check_sc;
typedef Pt  _favilla_bip32_check_Pt;
typedef JPt _favilla_bip32_check_JPt;

// ── HMAC-SHA512 helper ────────────────────────────────────────────────────
static void bip32_hmac_sha512(const uint8_t* key, size_t key_len,
                               const uint8_t* data, size_t data_len,
                               uint8_t out[64]) {
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, md, 1);
  mbedtls_md_hmac_starts(&ctx, key, key_len);
  mbedtls_md_hmac_update(&ctx, data, data_len);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// ── secp256k1 order n ─────────────────────────────────────────────────────
static const uint8_t BIP32_N_BYTES[32] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
  0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
  0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

// ── Extended key (private side) ───────────────────────────────────────────
typedef struct {
  uint8_t key[32];
  uint8_t chain_code[32];
  uint8_t depth;
  uint32_t child_number;
  uint8_t parent_fingerprint[4];
} bip32_xprv;

// ── Master key from seed ──────────────────────────────────────────────────
static bool bip32_master_from_seed(const uint8_t* seed, size_t seed_len,
                                    bip32_xprv* out) {
  MbedSecretScope _mbedSecret;   // 2 Nov 2026: keep this on-chip (mbed_secret.h)
  uint8_t I[64];
  bip32_hmac_sha512((const uint8_t*)"Bitcoin seed", 12, seed, seed_len, I);
  memcpy(out->key, I, 32);
  memcpy(out->chain_code, I + 32, 32);
  out->depth = 0;
  out->child_number = 0;
  memset(out->parent_fingerprint, 0, 4);
  return true;
}

// ── Compressed pubkey from privkey ────────────────────────────────────────
static bool bip32_priv_to_pub_compressed(const uint8_t priv32[32],
                                          uint8_t pub33_out[33]) {
  MbedSecretScope _mbedSecret;   // 2 Nov 2026: keep this on-chip (mbed_secret.h)
  sc d;
  sc_from_b32(&d, priv32);
  sc_reduce_once(&d);
  if (sc_is_zero(&d)) return false;

  JPt Pj;
  pt_mul_base(&Pj, &d);
  Pt P;
  jpt_to_affine(&P, &Pj);

  pub33_out[0] = fe_is_odd(&P.y) ? 0x03 : 0x02;
  fe_to_b32(pub33_out + 1, &P.x);
  return true;
}

// ── Child derivation ──────────────────────────────────────────────────────
static bool bip32_derive_child(const bip32_xprv* parent, uint32_t index,
                                bip32_xprv* out) {
  MbedSecretScope _mbedSecret;   // 2 Nov 2026: keep this on-chip (mbed_secret.h)
  uint8_t data[37];
  if (index >= 0x80000000UL) {
    data[0] = 0x00;
    memcpy(data + 1, parent->key, 32);
  } else {
    uint8_t parent_pub[33];
    if (!bip32_priv_to_pub_compressed(parent->key, parent_pub)) return false;
    memcpy(data, parent_pub, 33);
  }
  data[33] = (index >> 24) & 0xFF;
  data[34] = (index >> 16) & 0xFF;
  data[35] = (index >>  8) & 0xFF;
  data[36] =  index        & 0xFF;

  uint8_t I[64];
  bip32_hmac_sha512(parent->chain_code, 32, data, 37, I);

  mbedtls_mpi mN, mIL, mKey, mChild;
  mbedtls_mpi_init(&mN);   mbedtls_mpi_init(&mIL);
  mbedtls_mpi_init(&mKey); mbedtls_mpi_init(&mChild);

  mbedtls_mpi_read_binary(&mN,   BIP32_N_BYTES, 32);
  mbedtls_mpi_read_binary(&mIL,  I,             32);
  mbedtls_mpi_read_binary(&mKey, parent->key,   32);

  bool ok = true;
  if (mbedtls_mpi_cmp_mpi(&mIL, &mN) >= 0) {
    ok = false;
  } else {
    mbedtls_mpi_add_mpi(&mChild, &mIL, &mKey);
    mbedtls_mpi_mod_mpi(&mChild, &mChild, &mN);
    if (mbedtls_mpi_cmp_int(&mChild, 0) == 0) {
      ok = false;
    } else {
      mbedtls_mpi_write_binary(&mChild, out->key, 32);
      memcpy(out->chain_code, I + 32, 32);
      out->depth = parent->depth + 1;
      out->child_number = index;
      memset(out->parent_fingerprint, 0, 4);
    }
  }

  mbedtls_mpi_free(&mN);   mbedtls_mpi_free(&mIL);
  mbedtls_mpi_free(&mKey); mbedtls_mpi_free(&mChild);
  return ok;
}

static bool bip32_derive_path(const bip32_xprv* master,
                               const uint32_t* path, int path_len,
                               bip32_xprv* out) {
  MbedSecretScope _mbedSecret;   // 2 Nov 2026: keep this on-chip (mbed_secret.h)
  bip32_xprv cur = *master;
  for (int i = 0; i < path_len; i++) {
    bip32_xprv next;
    if (!bip32_derive_child(&cur, path[i], &next)) return false;
    cur = next;
  }
  *out = cur;
  return true;
}

// ════════════════════════════════════════════════════════════════════════
//  PUBLIC (watch-only) derivation — CKD-pub
// ════════════════════════════════════════════════════════════════════════
//
// This is the seed-free half of BIP-32. It lets the device verify change
// outputs and derive receive addresses from a cached account-level *public*
// key, with no private key and no seed in RAM. It is the foundation of the
// two-door design: the daily door can prove "this output is my change"
// without ever touching spend-bound material.
//
// CKD-pub only works for UNHARDENED children (index < 0x80000000). Hardened
// derivation structurally requires the private key — bip32_derive_child_pub
// returns false for hardened indices by design, never silently. The BIP-84
// address paths we care about (change/index) are unhardened, so this covers
// them; the hardened prefix m/84'/0'/0' must already have been walked on the
// private side at onboarding to produce the account xpub we start from.
//
// Math: for child i,
//   I       = HMAC-SHA512(cc_parent, ser_P(K_parent) || ser32(i))
//   I_L,I_R = I[0..32), I[32..64)
//   K_child = point(I_L) + K_parent      (elliptic-curve point addition)
//   cc_child= I_R
// Failure (caller must treat as "cannot derive", NOT as a valid key):
//   - hardened index
//   - I_L >= n
//   - K_child is the point at infinity   (point(I_L) == -K_parent)

// ── Extended key (public side) ────────────────────────────────────────────
typedef struct {
  uint8_t pubkey[33];          // compressed SEC point
  uint8_t chain_code[32];
  uint8_t depth;
  uint32_t child_number;
  uint8_t parent_fingerprint[4];
} bip32_xpub;

// ── Decompress a 33-byte SEC pubkey into an affine point ──────────────────
// Recovers y from x via y = sqrt(x^3 + 7), then fixes parity from the prefix
// byte. Returns false if the prefix is not 0x02/0x03, if x is out of field
// range, or if the recovered point is not actually on the curve (i.e. x^3+7
// was a non-residue — fe_sqrt returns a bogus root and we reject it via the
// on-curve recheck). The on-curve recheck is essential: without it a crafted
// pubkey could smuggle an off-curve point into the addition.
static bool bip32_pub_decompress(const uint8_t pub33[33], Pt* out) {
  if (pub33[0] != 0x02 && pub33[0] != 0x03) return false;

  fe x;
  fe_from_b32(&x, pub33 + 1);
  // Reject x >= p BEFORE any normalisation. fe_norm() reduces mod p (subtracts
  // p once), which would mask an out-of-range x by silently folding it into a
  // valid-looking coordinate. We must compare the raw deserialised limbs to the
  // field prime first; only then normalise.
  if (fe_cmp_raw(x.n, FE_P) >= 0) return false;
  fe_norm(&x);  // no-op now (x < p guaranteed), kept for limb-form consistency

  // rhs = x^3 + 7
  fe x2, x3, rhs, seven;
  fe_sqr(&x2, &x);
  fe_mul(&x3, &x2, &x);
  memset(&seven, 0, sizeof(seven));
  seven.n[0] = 7;
  fe_add(&rhs, &x3, &seven);
  fe_norm(&rhs);

  // y = sqrt(rhs)
  fe y;
  fe_sqrt(&y, &rhs);
  fe_norm(&y);

  // On-curve recheck: y^2 must equal rhs. fe_sqrt always returns *a* value;
  // only this check confirms rhs was a quadratic residue (point is real).
  fe y2;
  fe_sqr(&y2, &y);
  fe_norm(&y2);
  if (fe_cmp_raw(y2.n, rhs.n) != 0) return false;

  // Parity: prefix 0x02 => even y, 0x03 => odd y. Negate if mismatched.
  int want_odd = (pub33[0] == 0x03);
  if (fe_is_odd(&y) != want_odd) {
    fe_negate(&y, &y);
    fe_norm(&y);
  }

  out->x = x;
  out->y = y;
  out->inf = 0;
  return true;
}

// ── Compress an affine point into a 33-byte SEC pubkey ────────────────────
static void bip32_pub_compress(const Pt* p, uint8_t pub33_out[33]) {
  fe yy = p->y;
  fe_norm(&yy);
  pub33_out[0] = fe_is_odd(&yy) ? 0x03 : 0x02;
  fe xx = p->x;
  fe_norm(&xx);
  fe_to_b32(pub33_out + 1, &xx);
}

// ── Public child derivation (CKD-pub) ─────────────────────────────────────
// Derives an unhardened child PUBLIC key from a parent public key, with no
// private material. Returns false for hardened indices and for the two
// degenerate cases BIP-32 mandates skipping (I_L >= n, child == infinity).
static bool bip32_derive_child_pub(const bip32_xpub* parent, uint32_t index,
                                    bip32_xpub* out) {
  // Hardened derivation is impossible without the private key. Refuse loudly.
  if (index >= 0x80000000UL) return false;

  // data = ser_P(K_parent) || ser32(index)   (37 bytes: 33 + 4)
  uint8_t data[37];
  memcpy(data, parent->pubkey, 33);
  data[33] = (index >> 24) & 0xFF;
  data[34] = (index >> 16) & 0xFF;
  data[35] = (index >>  8) & 0xFF;
  data[36] =  index        & 0xFF;

  uint8_t I[64];
  bip32_hmac_sha512(parent->chain_code, 32, data, 37, I);

  // Reject I_L >= n. We reuse the field comparator on the raw 32-bit limbs,
  // so load I_L into an fe purely as a 256-bit big-endian container and
  // compare against the curve order n (BIP32_N_BYTES). This is a magnitude
  // comparison, not field arithmetic — no reduction is applied.
  {
    fe il_mag, n_mag;
    fe_from_b32(&il_mag, I);
    fe_from_b32(&n_mag, BIP32_N_BYTES);
    if (fe_cmp_raw(il_mag.n, n_mag.n) >= 0) return false;  // I_L >= n: skip
  }

  // point(I_L): scalar-multiply the generator by I_L.
  sc il;
  sc_from_b32(&il, I);
  sc_reduce_once(&il);           // I_L < n already guaranteed above
  JPt R;
  pt_mul_base(&R, &il);          // R = I_L * G  (Jacobian)

  // K_child = point(I_L) + K_parent. Decompress parent to affine and add.
  Pt parent_pt;
  if (!bip32_pub_decompress(parent->pubkey, &parent_pt)) return false;

  JPt sum;
  jpt_madd(&sum, &R, &parent_pt);   // handles R==inf, and the doubling/inf cases
  if (sum.inf) return false;        // child is point at infinity: skip index

  Pt child_pt;
  jpt_to_affine(&child_pt, &sum);
  if (child_pt.inf) return false;

  bip32_pub_compress(&child_pt, out->pubkey);
  memcpy(out->chain_code, I + 32, 32);
  out->depth = parent->depth + 1;
  out->child_number = index;
  memset(out->parent_fingerprint, 0, 4);
  return true;
}

// ── Convenience: account xprv → account xpub ──────────────────────────────
// Produces the public counterpart of a private extended key, so onboarding
// can cache the xpub (public, persistable) while the seed is briefly in RAM.
static bool bip32_xprv_to_xpub(const bip32_xprv* xprv, bip32_xpub* out) {
  if (!bip32_priv_to_pub_compressed(xprv->key, out->pubkey)) return false;
  memcpy(out->chain_code, xprv->chain_code, 32);
  out->depth = xprv->depth;
  out->child_number = xprv->child_number;
  memcpy(out->parent_fingerprint, xprv->parent_fingerprint, 4);
  return true;
}

#endif // FAVILLA_BIP32_H
