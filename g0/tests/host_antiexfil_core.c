/* 27 Oct 2026: anti-exfil cores (src/antiexfil.c) on the host with real
 * libsecp256k1.
 *   1. BIP-340: for all 15 vectors with a secret key, k0 from ae_schnorr_init
 *      equals the nonce BIP-340 itself would use (sign32 with the same aux'
 *      and a fixed-nonce k0 give byte-identical signatures), R0 = k0*G.
 *   2. BIP-340 FINISH: the tweaked signature verifies, and the host relation
 *      x(R0 + e*G) == sig[0..32] holds; a wrong t fails the relation; a
 *      signature made WITHOUT the tweak (today's path) fails the relation.
 *   3. ECDSA: same, DER r == x(R0 + e*G) mod n; recoverable variant recovers
 *      the right key; untweaked RFC 6979 signature fails the relation.
 *   4. Determinism: same inputs -> same (k0, R0, sig); different h -> different k0.
 *   5. Prints the fixed self-test vectors (sk, msg, aux, t -> R0, sig) for
 *      include/antiexfil_vectors.h when run with "gen". */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_recovery.h"
#include "secp256k1_preallocated.h"
#include "sha256.h"
#include "antiexfil.h"
#include "bip340_vectors.h"
#define BIP340_NVECS (sizeof(BIP340_VECS)/sizeof(BIP340_VECS[0]))
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;printf("ILLEGAL: %s\n",m);}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;printf("ERROR: %s\n",m);}
static secp256k1_context *ctx; static uint8_t ctxbuf[512] __attribute__((aligned(16)));
static int fails = 0, total = 0;
static void check(const char *n, int ok){ total++; if(!ok){ fails++; printf("FAIL %s\n", n);} }
static void hex(const char *l, const uint8_t *b, size_t n){ printf("%s", l); for(size_t i=0;i<n;i++) printf("%02x", b[i]); printf("\n"); }
static void fill(uint8_t *b, size_t n, uint8_t seed){ for(size_t i=0;i<n;i++) b[i] = (uint8_t)(seed*31 + i*7 + 3); }
static int fixed_h(unsigned char *n32,const unsigned char *m,size_t ml,const unsigned char *k,const unsigned char *p,const unsigned char *a,size_t al,void *d){(void)m;(void)ml;(void)k;(void)p;(void)a;(void)al;memcpy(n32,d,32);return 1;}

int main(int argc, char **argv) {
    int gen = argc > 1 && !strcmp(argv[1], "gen");
    ctx = secp256k1_context_preallocated_create(ctxbuf, SECP256K1_CONTEXT_NONE);
    uint8_t t[32], h[32], k0[32], r0[33], sig[64], sig2[64], aux[32], aux2[32];
    /* ── 1 + 2: BIP-340 ─────────────────────────────────────────────────── */
    for (size_t i = 0; i < BIP340_NVECS; i++) {
        const bip340_vec_t *v = &BIP340_VECS[i]; if (!v->has_sk) continue;
        fill(t, 32, (uint8_t)(i + 1)); ae_host_commit(AE_KIND_SCHNORR, t, h);
        memcpy(aux, v->aux, 32);
        check("schnorr init", ae_schnorr_init(ctx, v->sk, v->msg, aux, h, k0, r0) == 0);
        /* the k0 BIP-340 itself would use with aux' = SHA256(aux||h) */
        { sha256_ctx c; sha256_init(&c); sha256_update(&c, aux, 32); sha256_update(&c, h, 32); sha256_final(&c, aux2);
          secp256k1_keypair kp; secp256k1_schnorrsig_extraparams ep = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
          secp256k1_keypair_create(ctx, &kp, v->sk);
          check("sign32 aux'", secp256k1_schnorrsig_sign32(ctx, sig, v->msg, &kp, aux2));
          ep.noncefp = fixed_h; ep.ndata = k0;
          check("sign fixed k0", secp256k1_schnorrsig_sign_custom(ctx, sig2, v->msg, 32, &kp, &ep));
          check("k0 == BIP-340 nonce", memcmp(sig, sig2, 64) == 0); }
        { secp256k1_pubkey P; uint8_t s[33]; size_t l = 33; secp256k1_ec_pubkey_create(ctx, &P, k0);
          secp256k1_ec_pubkey_serialize(ctx, s, &l, &P, SECP256K1_EC_COMPRESSED); check("R0 = k0*G", memcmp(s, r0, 33) == 0); }
        check("schnorr finish", ae_schnorr_finish(ctx, v->sk, v->msg, k0, r0, t, sig) == 0);
        { secp256k1_xonly_pubkey pk; secp256k1_xonly_pubkey_parse(ctx, &pk, v->pk);
          check("tweaked sig verifies", secp256k1_schnorrsig_verify(ctx, sig, v->msg, 32, &pk)); }
        check("host relation", ae_host_check(ctx, AE_KIND_SCHNORR, r0, t, sig));
        { uint8_t tw[32]; memcpy(tw, t, 32); tw[5] ^= 1; check("wrong t fails", !ae_host_check(ctx, AE_KIND_SCHNORR, r0, tw, sig)); }
        check("untweaked (today) fails relation", !ae_host_check(ctx, AE_KIND_SCHNORR, r0, t, v->sig));
        check("tweaked != untweaked", memcmp(sig, v->sig, 64) != 0);
        { uint8_t k0b[32], r0b[33], sigb[64];
          check("init deterministic", ae_schnorr_init(ctx, v->sk, v->msg, aux, h, k0b, r0b) == 0 && !memcmp(k0b, k0, 32) && !memcmp(r0b, r0, 33));
          check("finish deterministic", ae_schnorr_finish(ctx, v->sk, v->msg, k0, r0, t, sigb) == 0 && !memcmp(sigb, sig, 64));
          uint8_t h2[32]; memcpy(h2, h, 32); h2[0] ^= 1;
          check("different h -> different k0", ae_schnorr_init(ctx, v->sk, v->msg, aux, h2, k0b, r0b) == 0 && memcmp(k0b, k0, 32) != 0); }
        if (gen && (i == 0 || i == 2)) {   /* two fixed vectors for the on-chip self-test */
            printf("/* schnorr vector from BIP-340 index %u */\n", v->idx);
            hex("sk  ", v->sk, 32); hex("msg ", v->msg, 32); hex("aux ", aux, 32); hex("t   ", t, 32); hex("h   ", h, 32); hex("r0  ", r0, 33); hex("sig ", sig, 64);
        }
    }
    /* ── 3: ECDSA ───────────────────────────────────────────────────────── */
    for (int i = 0; i < 6; i++) {
        uint8_t key[32], msg[32]; fill(key, 32, (uint8_t)(40 + i)); key[0] &= 0x7F; fill(msg, 32, (uint8_t)(80 + i));
        fill(t, 32, (uint8_t)(120 + i)); ae_host_commit(AE_KIND_ECDSA, t, h);
        check("ecdsa init", ae_ecdsa_init(ctx, key, msg, h, k0, r0) == 0);
        { unsigned char n2[32]; secp256k1_nonce_function_rfc6979(n2, msg, key, NULL, h, 0); check("k0 == rfc6979(extra=h)", !memcmp(n2, k0, 32)); }
        secp256k1_ecdsa_signature s, s0; uint8_t c[64], c0[64];
        check("ecdsa finish", ae_ecdsa_finish(ctx, AE_KIND_ECDSA, key, msg, k0, r0, t, &s, NULL) == 0);
        secp256k1_ecdsa_signature_serialize_compact(ctx, c, &s);
        { secp256k1_pubkey P; secp256k1_ec_pubkey_create(ctx, &P, key); check("tweaked ecdsa verifies", secp256k1_ecdsa_verify(ctx, &s, msg, &P)); }
        check("ecdsa host relation", ae_host_check(ctx, AE_KIND_ECDSA, r0, t, c));
        { uint8_t tw[32]; memcpy(tw, t, 32); tw[9] ^= 2; check("ecdsa wrong t fails", !ae_host_check(ctx, AE_KIND_ECDSA, r0, tw, c)); }
        secp256k1_ecdsa_sign(ctx, &s0, msg, key, NULL, NULL); secp256k1_ecdsa_signature_serialize_compact(ctx, c0, &s0);
        check("untweaked rfc6979 fails relation", !ae_host_check(ctx, AE_KIND_ECDSA, r0, t, c0));
        /* recoverable (BIP-137) */
        secp256k1_ecdsa_recoverable_signature rs; int recid = -1; uint8_t rc64[64];
        uint8_t hr[32]; ae_host_commit(AE_KIND_ECDSA_RC, t, hr); check("h same tag for ECDSA kinds", !memcmp(hr, h, 32));
        check("ecdsa_rc finish", ae_ecdsa_finish(ctx, AE_KIND_ECDSA_RC, key, msg, k0, r0, t, NULL, &rs) == 0);
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, rc64, &recid, &rs);
        check("rc r == plain r", !memcmp(rc64, c, 32) && !memcmp(rc64 + 32, c + 32, 32));
        check("rc host relation", ae_host_check(ctx, AE_KIND_ECDSA_RC, r0, t, rc64));
        { secp256k1_pubkey rec, P; uint8_t a[33], b[33]; size_t l = 33; secp256k1_ec_pubkey_create(ctx, &P, key);
          check("recover", secp256k1_ecdsa_recover(ctx, &rec, &rs, msg));
          secp256k1_ec_pubkey_serialize(ctx, a, &l, &rec, SECP256K1_EC_COMPRESSED); l = 33; secp256k1_ec_pubkey_serialize(ctx, b, &l, &P, SECP256K1_EC_COMPRESSED);
          check("recovers the key", !memcmp(a, b, 33)); }
        if (gen && i < 2) {
            printf("/* ecdsa vector %d */\n", i);
            hex("key ", key, 32); hex("msg ", msg, 32); hex("t   ", t, 32); hex("h   ", h, 32); hex("r0  ", r0, 33); hex("sig ", c, 64);
        }
    }
    /* tags are distinct between the two families */
    { uint8_t a[32], b[32]; fill(t, 32, 9); ae_host_commit(AE_KIND_SCHNORR, t, a); ae_host_commit(AE_KIND_ECDSA, t, b); check("data tags differ", memcmp(a, b, 32) != 0);
      fill(r0, 33, 3); r0[0] = 2; ae_tweak(AE_KIND_SCHNORR, r0, t, a); ae_tweak(AE_KIND_ECDSA, r0, t, b); check("point tags differ", memcmp(a, b, 32) != 0); }
    printf("antiexfil core: %d/%d passed%s\n", total - fails, total, fails ? "  <-- FAIL" : "");
    return fails ? 1 : 0;
}
