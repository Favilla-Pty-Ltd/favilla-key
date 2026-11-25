/* antiexfil.c — see antiexfil.h. 27 Oct 2026. */
#include "antiexfil.h"
#include "sha256.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_recovery.h"
#include <string.h>

static void wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }

/* BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data...). */
static void tagged_init(sha256_ctx *c, const char *tag) {
    uint8_t th[32];
    sha256((const uint8_t *)tag, strlen(tag), th);
    sha256_init(c);
    sha256_update(c, th, 32);
    sha256_update(c, th, 32);
}

static const char *tag_data(uint8_t kind)  { return kind == AE_KIND_SCHNORR ? "s2c/schnorr/data"  : "s2c/ecdsa/data"; }
static const char *tag_point(uint8_t kind) { return kind == AE_KIND_SCHNORR ? "s2c/schnorr/point" : "s2c/ecdsa/point"; }

void ae_host_commit(uint8_t kind, const uint8_t t[32], uint8_t h[32]) {
    sha256_ctx c; tagged_init(&c, tag_data(kind));
    sha256_update(&c, t, 32); sha256_final(&c, h);
}

void ae_tweak(uint8_t kind, const uint8_t r0[33], const uint8_t t[32], uint8_t e[32]) {
    sha256_ctx c; tagged_init(&c, tag_point(kind));
    sha256_update(&c, r0, 33); sha256_update(&c, t, 32); sha256_final(&c, e);
}

/* The nonce the signing entry points will use is handed in through ndata.
 * Any retry (counter != 0) is refused: the tweaked k is valid or we fail. */
static int nonce_fixed(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32,
                       const unsigned char *algo16, void *data, unsigned int counter) {
    (void)msg32; (void)key32; (void)algo16;
    if (counter != 0 || data == NULL) return 0;
    memcpy(nonce32, data, 32);
    return 1;
}
static int nonce_fixed_hardened(unsigned char *nonce32, const unsigned char *msg, size_t msglen,
                                const unsigned char *key32, const unsigned char *xonly_pk32,
                                const unsigned char *algo, size_t algolen, void *data) {
    (void)msg; (void)msglen; (void)key32; (void)xonly_pk32; (void)algo; (void)algolen;
    if (data == NULL) return 0;
    memcpy(nonce32, data, 32);
    return 1;
}

static int point_of(const secp256k1_context *ctx, const uint8_t k[32], uint8_t out33[33]) {
    secp256k1_pubkey p; size_t l = 33;
    if (!secp256k1_ec_pubkey_create(ctx, &p, k)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, out33, &l, &p, SECP256K1_EC_COMPRESSED) || l != 33) return 0;
    return 1;
}

/* k = k0 + e mod n, refusing 0 (secp256k1_ec_seckey_tweak_add does both). */
#ifdef BENCH_LEAKY_NONCE
uint8_t g_bench_leak_byte = 0;   /* set by the caller to key[0] before FINISH */
#endif
static int tweak_nonce(const secp256k1_context *ctx, uint8_t kind, const uint8_t k0[32], const uint8_t r0[33],
                       const uint8_t t[32], uint8_t k[32]) {
    uint8_t e[32]; int ok;
    ae_tweak(kind, r0, t, e);
    memcpy(k, k0, 32);
    ok = secp256k1_ec_seckey_tweak_add(ctx, k, e);   /* fails if e >= n or k == 0 */
    wipe(e, 32);
    if (!ok) wipe(k, 32);
#ifdef BENCH_LEAKY_NONCE
    /* BENCH ONLY (acceptance test 4): a dishonest G0 that ignores t and puts
     * 8 key bits in the final nonce. The signatures stay valid; the host
     * relation x(R0 + H(R0||t)G) == r fails on every one. A build with this
     * flag must never leave the bench: the firmware image is rebuilt without
     * it and its hash recorded before any board ships. */
    memcpy(k, k0, 32); k[31] = g_bench_leak_byte;
    ok = secp256k1_ec_seckey_verify(ctx, k);
#endif
    return ok;
}

/* ── BIP-340 ─────────────────────────────────────────────────────────────── */
static const unsigned char bip340_algo[13] = {'B','I','P','0','3','4','0','/','n','o','n','c','e'};

int ae_schnorr_init(const secp256k1_context *ctx, const uint8_t scalar[32],
                    const uint8_t msg[32], const uint8_t aux[32], const uint8_t h[32],
                    uint8_t k0[32], uint8_t r0[33]) {
    secp256k1_keypair kp; secp256k1_xonly_pubkey pk; int parity = 0, rc = -1;
    uint8_t dprime[32], pk32[32], aux2[32];
    if (!secp256k1_keypair_create(ctx, &kp, scalar)) return -1;
    if (!secp256k1_keypair_xonly_pub(ctx, &pk, &parity, &kp)) goto out;
    secp256k1_xonly_pubkey_serialize(ctx, pk32, &pk);
    /* d' = the even-Y secret, exactly as secp256k1_schnorrsig_sign_internal
     * hands it to the nonce function. */
    memcpy(dprime, scalar, 32);
    if (parity && !secp256k1_ec_seckey_negate(ctx, dprime)) goto out;
    /* aux' = SHA256(aux || h): the caller's aux_rand with the host commitment
     * folded in, so a replayed or lost t never gives this message a second
     * nonce with the same k0 on a different (t, h). */
    { sha256_ctx c; sha256_init(&c); sha256_update(&c, aux, 32); sha256_update(&c, h, 32); sha256_final(&c, aux2); }
    if (!secp256k1_nonce_function_bip340(k0, msg, 32, dprime, pk32, bip340_algo, sizeof(bip340_algo), aux2)) goto out;
    if (!secp256k1_ec_seckey_verify(ctx, k0)) goto out;   /* k0 == 0 or >= n: refuse (BIP-340 says fail) */
    if (!point_of(ctx, k0, r0)) goto out;
    rc = 0;
out:
    wipe(&kp, sizeof(kp)); wipe(dprime, 32); wipe(aux2, 32);
    if (rc) { wipe(k0, 32); wipe(r0, 33); }
    return rc;
}

int ae_schnorr_finish(const secp256k1_context *ctx, const uint8_t scalar[32],
                      const uint8_t msg[32], const uint8_t k0[32], const uint8_t r0[33],
                      const uint8_t t[32], uint8_t sig64[64]) {
    secp256k1_keypair kp; uint8_t k[32]; int rc = -1;
    secp256k1_schnorrsig_extraparams ep = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
#ifdef BENCH_LEAKY_NONCE
    g_bench_leak_byte = scalar[0];
#endif
    if (!tweak_nonce(ctx, AE_KIND_SCHNORR, k0, r0, t, k)) return -1;
    if (!secp256k1_keypair_create(ctx, &kp, scalar)) goto out;
    ep.noncefp = nonce_fixed_hardened; ep.ndata = k;
    /* libsecp256k1 computes R = k*G, negates k if R has odd Y, e = H(R.x||P||m),
     * s = k + e*d'. The host compares x only, so the negation is invisible. */
    if (!secp256k1_schnorrsig_sign_custom(ctx, sig64, msg, 32, &kp, &ep)) goto out;
    rc = 0;
out:
    wipe(&kp, sizeof(kp)); wipe(k, 32);
    if (rc) wipe(sig64, 64);
    return rc;
}

/* ── ECDSA ───────────────────────────────────────────────────────────────── */
int ae_ecdsa_init(const secp256k1_context *ctx, const uint8_t key[32],
                  const uint8_t msg[32], const uint8_t h[32],
                  uint8_t k0[32], uint8_t r0[33]) {
    uint8_t hh[32]; unsigned int counter; int rc = -1;
    memcpy(hh, h, 32);
    /* RFC 6979 with h as the 32-byte extra data, counter bumped only if the
     * candidate is not a valid scalar (as secp256k1_ecdsa_sign itself does). */
    for (counter = 0; counter < 8; counter++) {
        if (!secp256k1_nonce_function_rfc6979(k0, msg, key, NULL, hh, counter)) goto out;
        if (secp256k1_ec_seckey_verify(ctx, k0)) break;
    }
    if (counter == 8) goto out;
    if (!point_of(ctx, k0, r0)) goto out;
    rc = 0;
out:
    wipe(hh, 32);
    if (rc) { wipe(k0, 32); wipe(r0, 33); }
    return rc;
}

int ae_ecdsa_finish(const secp256k1_context *ctx, uint8_t kind, const uint8_t key[32],
                    const uint8_t msg[32], const uint8_t k0[32], const uint8_t r0[33],
                    const uint8_t t[32], secp256k1_ecdsa_signature *sig,
                    secp256k1_ecdsa_recoverable_signature *rsig) {
    uint8_t k[32]; int rc = -1;
    if (kind != AE_KIND_ECDSA && kind != AE_KIND_ECDSA_RC) return -1;
#ifdef BENCH_LEAKY_NONCE
    g_bench_leak_byte = key[0];
#endif
    if (!tweak_nonce(ctx, kind, k0, r0, t, k)) return -1;
    /* r = x(k*G) mod n; low-S normalisation negates s, never k, so r is the
     * value the host predicts from R0 and t. */
    if (kind == AE_KIND_ECDSA) {
        if (!sig || !secp256k1_ecdsa_sign(ctx, sig, msg, key, nonce_fixed, k)) goto out;
    } else {
        if (!rsig || !secp256k1_ecdsa_sign_recoverable(ctx, rsig, msg, key, nonce_fixed, k)) goto out;
    }
    rc = 0;
out:
    wipe(k, 32);
    return rc;
}

/* ── the host-side relation ──────────────────────────────────────────────── */
int ae_host_check(const secp256k1_context *ctx, uint8_t kind, const uint8_t r0[33],
                  const uint8_t t[32], const uint8_t r32[32]) {
    secp256k1_pubkey R0; uint8_t e[32], ser[33]; size_t l = 33;
    if (!secp256k1_ec_pubkey_parse(ctx, &R0, r0, 33)) return 0;
    ae_tweak(kind, r0, t, e);
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &R0, e)) return 0;      /* R0 + e*G */
    if (!secp256k1_ec_pubkey_serialize(ctx, ser, &l, &R0, SECP256K1_EC_COMPRESSED) || l != 33) return 0;
    if (kind == AE_KIND_SCHNORR) return memcmp(ser + 1, r32, 32) == 0;   /* field x, as BIP-340 serialises R */
    /* ECDSA: r = x mod n. x >= n happens with probability ~2^-128; reduce by
     * one subtraction if so, compared as big-endian bytes. */
    {
        static const uint8_t N[32] = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
        uint8_t x[32]; memcpy(x, ser + 1, 32);
        if (memcmp(x, N, 32) >= 0) { int borrow = 0; for (int i = 31; i >= 0; i--) { int d = (int)x[i] - N[i] - borrow; borrow = d < 0; x[i] = (uint8_t)d; } }
        return memcmp(x, r32, 32) == 0;
    }
}
