/* =============================================================================
 * antiexfil.h — host-contributed nonce (anti-exfil) for every signature this
 * chip makes. Added 27 Oct 2026 ("Anti-exfil signing on the Favilla KEY").
 * =============================================================================
 *
 * The problem: a signature is public, its nonce k is secret, and k and the
 * private key are linked by the signature equation. A signer that picks k on
 * its own can leak the key through a pattern in k that only an attacker who
 * reads public signatures can see. Today's RFC 6979 / BIP-340 derivation is
 * correct, but the ESP32 cannot tell a correct k from a chosen one.
 *
 * The fix (Blockstream / Coldcard anti-exfil, "sign-to-contract"): two round
 * trips instead of one.
 *
 *   host:   t = 32 random bytes,  h = TAGGED_DATA(t)        (commit to t)
 *   INIT:   k0 = deterministic nonce(key, msg, extra = h),  R0 = k0*G  -> host
 *   host:   reveal t
 *   FINISH: check TAGGED_DATA(t) == h
 *           e  = TAGGED_POINT(ser33(R0) || t)
 *           k  = k0 + e mod n,  sign with this k                -> signature
 *   host:   check  x(R0 + e*G) == r      (ECDSA: r;  BIP-340: sig[0..32])
 *           then verify the signature as usual
 *
 * The G0 commits to R0 before it learns t, so k0 cannot be a function of t;
 * the host commits to h before it learns R0, so neither side can grind the
 * final nonce. Every bit of k depends on t, which the G0 did not choose, so
 * any pattern the G0 tried to put in k0 is destroyed. The host learns nothing
 * it did not already see (R0 and the signature are both public-safe), and it
 * cannot choose k either: t only tweaks a nonce derived in-chip (invariant 2).
 *
 * Tags. ECDSA (BIP-143 inputs and BIP-137 messages) uses libsecp256k1-zkp's
 * ecdsa_s2c tags so Jade / Sparrow-class tooling can check a KEY signature
 * the same way:
 *     TAGGED_DATA  = SHA256-tagged("s2c/ecdsa/data")
 *     TAGGED_POINT = SHA256-tagged("s2c/ecdsa/point")
 * BIP-340 (Nostr) uses the tags of the upstream Schnorr sign-to-contract
 * proposal (bitcoin-core/secp256k1 PR 1140):
 *     TAGGED_DATA  = SHA256-tagged("s2c/schnorr/data")
 *     TAGGED_POINT = SHA256-tagged("s2c/schnorr/point")
 * where SHA256-tagged(tag)(x) = SHA256(SHA256(tag) || SHA256(tag) || x), the
 * BIP-340 tagged-hash convention. The two tag families keep the two tweaks
 * domain-separated on the one chip.
 *
 * k0 derivation (so a lost or replayed t never repeats a nonce on another
 * message):
 *   ECDSA:   k0 = RFC 6979(key, msg, extra data = h)   (libsecp256k1's own
 *            secp256k1_nonce_function_rfc6979, counter 0, bumped if invalid)
 *   BIP-340: k0 = BIP-340 nonce(d', msg, aux) with aux = SHA256(K_G0 || msg ||
 *            fresh || h) — the existing key-bound, pool-mixed aux with h
 *            appended; d' is the even-Y secret exactly as libsecp256k1 signs.
 *
 * The cores below are stateless (key in, bytes out) so the host KATs and the
 * on-chip self-test run the very same code the commands run. Pending-state
 * handling (one operation at a time, 10 s timeout, wipe on RESET / Stop) is in
 * main.c.
 * ========================================================================== */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"
#include "secp256k1_recovery.h"

#define AE_KIND_NONE     0
#define AE_KIND_SCHNORR  1   /* Nostr SIGN */
#define AE_KIND_ECDSA    2   /* BTCSIGN (BIP-143, DER) */
#define AE_KIND_ECDSA_RC 3   /* MSGSIGN (BIP-137, recoverable) */

/* Host commitment h = TAGGED_DATA(t) for the kind. */
void ae_host_commit(uint8_t kind, const uint8_t t[32], uint8_t h[32]);
/* Tweak e = TAGGED_POINT(r0 || t) for the kind (32 bytes, a scalar mod n is
 * taken by the caller). */
void ae_tweak(uint8_t kind, const uint8_t r0[33], const uint8_t t[32], uint8_t e[32]);

/* BIP-340 INIT: k0 from (scalar, msg, aux, h), R0 = k0*G compressed.
 * aux is the caller's aux_rand (the h is appended inside). 0 ok. */
int ae_schnorr_init(const secp256k1_context *ctx, const uint8_t scalar[32],
                    const uint8_t msg[32], const uint8_t aux[32], const uint8_t h[32],
                    uint8_t k0[32], uint8_t r0[33]);
/* BIP-340 FINISH: sig64 with nonce k = k0 + TAGGED_POINT(r0||t). The caller
 * verifies the result against the true pubkey before release. 0 ok. */
int ae_schnorr_finish(const secp256k1_context *ctx, const uint8_t scalar[32],
                      const uint8_t msg[32], const uint8_t k0[32], const uint8_t r0[33],
                      const uint8_t t[32], uint8_t sig64[64]);

/* ECDSA INIT: k0 = RFC 6979(key, msg, extra = h), R0 = k0*G. 0 ok. */
int ae_ecdsa_init(const secp256k1_context *ctx, const uint8_t key[32],
                  const uint8_t msg[32], const uint8_t h[32],
                  uint8_t k0[32], uint8_t r0[33]);
/* ECDSA FINISH (kind ECDSA: plain signature out; kind ECDSA_RC: recoverable
 * signature out). Exactly one of sig / rsig is used. 0 ok. */
int ae_ecdsa_finish(const secp256k1_context *ctx, uint8_t kind, const uint8_t key[32],
                    const uint8_t msg[32], const uint8_t k0[32], const uint8_t r0[33],
                    const uint8_t t[32], secp256k1_ecdsa_signature *sig,
                    secp256k1_ecdsa_recoverable_signature *rsig);

/* The host-side check, also used by the self-test: 1 if x(R0 + e*G) == r
 * where r is the 32-byte nonce x-coordinate from the signature (BIP-340
 * sig[0..32], or ECDSA r). r is compared as a scalar mod n for ECDSA (r is
 * already reduced there) and as field bytes for BIP-340. */
int ae_host_check(const secp256k1_context *ctx, uint8_t kind, const uint8_t r0[33],
                  const uint8_t t[32], const uint8_t r32[32]);
