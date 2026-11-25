/* 19 Oct 2026: fault hardening of the G0 Nostr signer. Runs the REAL
 * do_sign_init() / do_ae_finish() from src/main.c (extracted; 27 Oct 2026:
 * the anti-exfil split, same checks) with real libsecp256k1:
 *   1. a normal signature verifies against the key's x-only pubkey
 *   2. the same message signed twice gives two DIFFERENT valid signatures
 *      (fresh pool bytes in aux_rand: no repeated nonce for a fault pair)
 *   3. a glitch that flips one bit of the signature is caught: rc != 0, wiped
 *   4. a glitch that flips one bit of the KEY before signing (signature valid
 *      for the wrong key, leaks a key bit) is caught by verifying against the
 *      cached true pubkey: rc != 0, wiped */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_preallocated.h"
#include "sha256.h"
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;printf("ILLEGAL: %s\n",m);}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;printf("ERROR: %s\n",m);}
#define KG0_LEN 32
static secp256k1_context *g_ctx; static uint8_t g_ctxbuf[512] __attribute__((aligned(16)));
static uint8_t g_kg0[KG0_LEN], g_hash_in[32], g_sig_out[64], g_pool[32];
#include "antiexfil.h"
#define AE_IN_LEN 64
#define AE_TIMEOUT_MS 10000
#define BTC_OUT_LEN 192
#define BTCSIGN_VER 3
#define MSGSIGN_VER_AE 2
static uint8_t g_btc_out[BTC_OUT_LEN];
static uint32_t HAL_GetTick(void){ return 1000; }
static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
/* btc release helpers are not reached by these checks */
int btc_sign_release(const secp256k1_context *c, const uint8_t *k, const uint8_t *m, const uint8_t *p, const secp256k1_ecdsa_signature *s, uint8_t *d, uint8_t *dl){(void)c;(void)k;(void)m;(void)p;(void)s;(void)d;(void)dl;return -3;}
int btc_msg_release(const secp256k1_context *c, const uint8_t *m, const uint8_t *p, const secp256k1_ecdsa_recoverable_signature *r, uint8_t *s){(void)c;(void)m;(void)p;(void)r;(void)s;return -3;}
static const uint8_t SK[32] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,
                               0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x12};
static void secure_wipe(void *p, size_t n){ volatile uint8_t *v = p; while(n--) *v++ = 0; }
static uint32_t tick = 0;
static void entropy_mix(const uint8_t *d, size_t n){ sha256_ctx c; sha256_init(&c); sha256_update(&c, g_pool, 32);
  tick++; sha256_update(&c, (const uint8_t*)&tick, 4); if(d&&n) sha256_update(&c, d, n); sha256_final(&c, g_pool); }
static int key_glitch = 0, fetches = 0;
static int fetch_scalar(uint8_t s[32]){ fetches++; memcpy(s, SK, 32); if (key_glitch == 1) { s[7] ^= 0x10; key_glitch = 2; } return 0; }   /* one bit of the key flipped on ONE load */
static int glitch = 0, calls = 0;
static void ctx_reblind(void){ unsigned char sd[32]; memset(sd, (int)(++calls), 32); (void)secp256k1_context_randomize(g_ctx, sd); }
static int faulty_sign_custom(const secp256k1_context *ctx, unsigned char *sig, const unsigned char *msg, size_t ml, const secp256k1_keypair *kp, secp256k1_schnorrsig_extraparams *ep){
  int r = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, ml, kp, ep);
  if (glitch == 1) { sig[40] ^= 0x04; glitch = 2; }   /* one bit of s corrupted in ONE run */
  return r; }
#define secp256k1_schnorrsig_sign_custom faulty_sign_custom
#include "../src/antiexfil.c"
#undef secp256k1_schnorrsig_sign_custom
#include "extracted_ae_state.inc"
#include "extracted_sign.inc"
/* the ESP32's two round trips */
static uint8_t T[32];
static int do_sign(void){
  uint8_t h[32]; memset(T, 0x77, 32); ae_host_commit(AE_KIND_SCHNORR, T, h);
  memcpy(g_ae_in, g_hash_in, 32); memcpy(g_ae_in + 32, h, 32); g_ae_in_valid = 1;
  secure_wipe(g_sig_out, 64);                       /* main(): previous result is gone */
  int rc = do_sign_init(); secure_wipe(g_ae_in, 64); g_ae_in_valid = 0;
  if (rc) secure_wipe(g_sig_out, 64);               /* finish(rc != 0) */
  if (rc) return rc;
  uint8_t r0[33]; memcpy(r0, g_sig_out, 33);
  memcpy(g_ae_t, T, 32); g_ae_t_valid = 1;
  secure_wipe(g_sig_out, 64);
  rc = do_ae_finish(); secure_wipe(g_ae_t, 32); g_ae_t_valid = 0;
  if (rc) secure_wipe(g_sig_out, 64);
  if (rc == 0 && !ae_host_check(g_ctx, AE_KIND_SCHNORR, r0, T, g_sig_out)) { printf("ANTI-EXFIL FAULT\n"); secure_wipe(g_sig_out, 64); return -9; }
  return rc; }
static int fails = 0;
#define CHECK(c,m) do{ if(c) printf("PASS  %s\n", m); else { printf("FAIL  %s\n", m); fails++; } }while(0)
int main(void){
  g_ctx = secp256k1_context_preallocated_create(g_ctxbuf, SECP256K1_CONTEXT_NONE);
  memset(g_kg0, 0x5a, 32); memset(g_hash_in, 0xab, 32);
  secp256k1_keypair kp; secp256k1_xonly_pubkey xpk; if(!secp256k1_keypair_create(g_ctx, &kp, SK)) return 1; secp256k1_keypair_xonly_pub(g_ctx, &xpk, NULL, &kp);
  uint8_t s1[64], s2[64], zero[64] = {0};
  int rc = do_sign();
  CHECK(rc != 0 && memcmp(g_sig_out, zero, 64) == 0, "sign before any PUBKEY this life: refused (fills the reference, signs nothing)");
  g_true_pk_ok = 0;                       /* now the normal order: PUBKEY at unlock, then signing */
  rc = do_pubkey(); uint8_t xs[32]; secp256k1_xonly_pubkey_serialize(g_ctx, xs, &xpk);
  CHECK(rc == 0 && memcmp(g_sig_out, xs, 32) == 0 && g_true_pk_ok, "PUBKEY returns the key and fills the reference (one fetch)");
  rc = do_sign(); memcpy(s1, g_sig_out, 64);
  CHECK(rc == 0 && secp256k1_schnorrsig_verify(g_ctx, s1, g_hash_in, 32, &xpk), "normal signature verifies");
  rc = do_sign(); memcpy(s2, g_sig_out, 64);
  CHECK(rc == 0 && secp256k1_schnorrsig_verify(g_ctx, s2, g_hash_in, 32, &xpk), "second signature of the same message verifies");
  CHECK(memcmp(s1, s2, 32) != 0, "same message, different nonce R (no repeated nonce for a fault pair)");
  glitch = 1; rc = do_sign(); glitch = 0;
  CHECK(rc != 0 && memcmp(g_sig_out, zero, 64) == 0, "glitched signature caught: rc != 0, output wiped");
  key_glitch = 1; rc = do_sign();
  CHECK(key_glitch == 2, "key glitch was injected on the signing load");
  CHECK(rc != 0 && memcmp(g_sig_out, zero, 64) == 0, "key-bit glitch caught (valid sig for the wrong key never leaves)");
  rc = do_sign();
  CHECK(rc == 0 && secp256k1_schnorrsig_verify(g_ctx, g_sig_out, g_hash_in, 32, &xpk), "next clean signature works again");
  { int f0 = fetches; (void)do_sign(); CHECK(fetches - f0 == 1, "a sign uses exactly ONE key fetch (one SE session, fits the relay guard)"); }
  printf(fails ? "\n%d FAILED\n" : "\nall fault-hardening checks passed\n", fails);
  return fails != 0; }
