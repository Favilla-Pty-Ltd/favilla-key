/* Restorable passkeys host test (30 Oct 2026, v2 after review). Runs the REAL
 * src/pk_glue.inc and the REAL kg0_iv / kg0_seal from main.c (extracted by
 * run_pk_test.sh) against a fake SE that models:
 *   - the master blob: sealed by PKMASTER, read back the way fetch_scalar_se
 *     does (K_G0 CBC decrypt with the SCALAR IV);
 *   - the scratch P-256 object: owner/policy, delete, create, private-only
 *     write, sign (mbedtls), and a write that lands but answers with a bad MAC
 *     (the session is then dead);
 *   - a planted object the G0 may not delete.
 * Checks Python KATs, recovers the public key from REGISTER's two signatures
 * with the same pkrecover.inc the ESP32 builds, and drives every failure path. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
#include "aes.h"
#include "scp03.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/private_access.h"

/* ---- the slice of main.c that pk_glue.inc uses ---- */
uint32_t g_gen_off = 0x100;   /* generation 1 */
#include "se_objects.h"
#define BTC_OUT_LEN 192
#define KG0_LEN 32
static uint8_t g_btc_out[BTC_OUT_LEN], g_sig_out[64], g_sesdiag[64], g_pool[32], g_kse[16], g_kg0[KG0_LEN];
static uint8_t g_hash_in[32]; static int g_hash_in_valid;
static int g_keys_valid = 1, g_door1_locked = 1, g_seal_window = 1;
/* 2 Nov 2026 (2b): the door decides which master copy and which outer key */
#define DOOR_UNSET 0
#define DOOR_NOSTR 1
#define DOOR_BTC 2
#define DOOR_PASSKEY 3
static uint8_t g_door = DOOR_PASSKEY;   /* v19: PKSIGN runs only in a PASSKEY life */
#define VLT_REFILLS_MAX 4u
static uint8_t g_vlt_refills = 0; static int life_saves = 0;
#define VLT_LABEL_PER_LIFE 800u
static uint16_t g_lbl_used = 0; static uint8_t g_imp_used = 0;   /* v15: main.c, life token word 2 */
static void life_save(void) { life_saves++; }
static int daily_used = 0;   /* the daily wrap key must never be asked for any more (S3) */
static void secure_wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }
static void entropy_mix(const uint8_t *d, size_t n) {
    static uint32_t ctr; sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_pool, 32); if (d && n) sha256_update(&c, d, n);
    ctr++; sha256_update(&c, (uint8_t *)&ctr, 4); sha256_final(&c, g_pool);
}
#include "hedge.inc"   /* v18: the firmware's own hedge32 */
static void host_challenge(uint8_t hc[8]) { uint8_t h[32]; entropy_mix((const uint8_t *)"hc", 2); sha256(g_pool, 32, h); memcpy(hc, h, 8); }
static int relay_xfer(void *c, const uint8_t *a, size_t al, uint8_t *r, size_t rc, size_t *rl) { (void)c;(void)a;(void)al;(void)r;(void)rc;(void)rl; return -1; }
#include "extracted_pk.inc"   /* REAL kg0_iv + kg0_seal from main.c */

/* ---- fake SE ---- */
static mbedtls_ecp_group G;
enum { OWN_NONE, OWN_G0, OWN_ROGUE_NODEL, OWN_ROGUE_DEL };
static int sc_exists = 0, sc_owner = OWN_NONE; static uint8_t se_slot[32];
static uint8_t se_master_blob[32], se_master_tag[32]; static int master_ok = 0;

static int fail_open, fail_write_n = -1, fail_write_from = -1, badmac_write_n = -1, fail_sign, fail_create;
static int writes, signs, opens, closes, fetches, deletes, creates, sessions_live, policy_ok;
static uint8_t hist[8][32]; static int hist_n;

/* The master object: ReadObject gives IV16 || CT32 of the SE's daily-wrap layer;
 * here that layer is the identity (CipherOneShot returns its input), so CT32 is
 * the G0's K_G0 layer exactly as PKMASTER made it. Readable only to the G0's
 * session while the Door-1 PCR is unlocked (modelled by g_door1_locked). */
/* v19: the G0 has NO right on K_PK or PK_MASTER_P (nor the old K_PKN /
 * PK_MASTER). Any attempt is counted and refused, as the SE now does. */
static int master_obj_touched = 0;
int scp03_read_object(scp03_session_t *s, uint32_t obj, uint8_t *out, size_t ocap, size_t *olen) {
    (void)out;(void)ocap;(void)olen; s->nxfer++;
    if (obj == SE_OBJ_PK_MASTER_P || obj == SE_OBJ_PK_MASTER) master_obj_touched++;
    s->last_sw = 0x6986; return SCP03_E_SW;
}
int scp03_cipher_oneshot(scp03_session_t *s, uint32_t key_obj, int decrypt, const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]) {
    (void)iv;(void)decrypt;(void)in;(void)out; s->nxfer++;
    if (key_obj == SE_OBJ_AES_WRAP_DAILY) daily_used++;
    if (key_obj == SE_OBJ_K_PK || key_obj == SE_OBJ_K_PKN) master_obj_touched++;
    s->last_sw = 0x6986; return SCP03_E_SW;
}
/* The latch read the G0 does in its own session (main.c's g0_read_mode_pcr). It
 * reads V_3 only while a passkey window is open (modelled by fake_pcr). */
static uint8_t fake_pcr[32]; static int pcr_fail = 0;
static int g0_read_mode_pcr(scp03_session_t *s, uint8_t out[32]) {
    s->nxfer++; fetches++;
    if (!s->authed || s->stage == 99) { s->last_sw = 0; return SCP03_E_RMAC; }
    if (pcr_fail) { s->last_sw = 0x6985; return SCP03_E_SW; }
    memcpy(out, fake_pcr, 32); s->last_sw = 0x9000; return 0;
}
static void door_secret(uint8_t d, uint8_t out[32]) { uint8_t b[33]; memcpy(b, "FAKE-S-DOOR-SECRET-FOR-HOST-TEST", 32); b[32] = d; sha256(b, 33, out); }
static void v3_value(uint8_t v3[32]) { uint8_t z[32] = {0}, b[64], sd[32]; door_secret(DOOR_PASSKEY, sd); sha256(z, 32, b); memcpy(b + 32, sd, 32); sha256(b, 64, v3); }
int scp03_open(scp03_session_t *s, scp03_xfer_fn x, void *xc, const uint8_t kse[16], uint32_t auth, const uint8_t hc[8], uint8_t cc[8]) {
    (void)x;(void)xc;(void)kse;(void)hc;
    opens++; memset(s, 0, sizeof(*s));
    if (auth != SE_AUTH_OBJ_G0 || fail_open) { s->stage = 1; s->last_sw = 0x6982; return SCP03_E_SW; }
    for (int i = 0; i < 8; i++) cc[i] = (uint8_t)rand();
    s->authed = 1; s->stage = SCP03_ST_AUTHED; sessions_live++; return 0;
}
int scp03_close(scp03_session_t *s) { uint16_t sw = s->last_sw; if (s->authed) { closes++; sessions_live--; } memset(s, 0, sizeof(*s)); s->last_sw = sw; s->stage = SCP03_ST_CLOSED; return 0; }
void scp03_wipe(scp03_session_t *s) { memset(s, 0, sizeof(*s)); }
static int dead(scp03_session_t *s) { return s->stage == 99; }
static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
int scp03_cmd(scp03_session_t *s, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *d, size_t n, int hasle, uint8_t *out, size_t ocap, size_t *olen) {
    (void)hasle;(void)out;(void)ocap;(void)olen;
    s->nxfer++;
    if (!s->authed || dead(s)) { s->last_sw = 0; return SCP03_E_RMAC; }
    if (ins == 0x04 && p2 == 0x28) {                       /* DeleteSecureObject */
        if (n != 6 || d[0] != 0x41 || be32(d + 2) != SE_OBJ_PK_SCRATCH) { s->last_sw = 0x6A80; return SCP03_E_SW; }
        deletes++;
        if (!sc_exists) { s->last_sw = 0x6A82; return SCP03_E_SW; }
        if (sc_owner == OWN_ROGUE_NODEL) { s->last_sw = 0x6986; return SCP03_E_SW; }
        sc_exists = 0; sc_owner = OWN_NONE; s->last_sw = 0x9000; return 0;
    }
    if (ins == 0x01 && p1 == 0x41 && n > 2 && d[0] == 0x11) { /* WriteECKey create with policy */
        creates++;
        if (sc_exists || fail_create) { s->last_sw = 0x6A80; return SCP03_E_SW; }
        uint8_t want[20]; size_t w = 0;   /* exactly: G0 SIGN|WRITE|DELETE, RECOVER DELETE */
        want[w++] = 0x11; want[w++] = 18;
        want[w++] = 8; want[w++] = (uint8_t)(SE_AUTH_OBJ_G0 >> 24); want[w++] = (uint8_t)(SE_AUTH_OBJ_G0 >> 16); want[w++] = (uint8_t)(SE_AUTH_OBJ_G0 >> 8); want[w++] = (uint8_t)SE_AUTH_OBJ_G0;
        want[w++] = 0x10; want[w++] = 0x14; want[w++] = 0; want[w++] = 0;
        want[w++] = 8; want[w++] = (uint8_t)(SE_AUTH_OBJ_RECOVER >> 24); want[w++] = (uint8_t)(SE_AUTH_OBJ_RECOVER >> 16); want[w++] = (uint8_t)(SE_AUTH_OBJ_RECOVER >> 8); want[w++] = (uint8_t)SE_AUTH_OBJ_RECOVER;
        want[w++] = 0x00; want[w++] = 0x04; want[w++] = 0x00; want[w++] = 0x00;
        policy_ok = (w == 20 && n == 63 && !memcmp(d, want, 20) &&
                     d[20] == 0x41 && d[21] == 4 && be32(d + 22) == SE_OBJ_PK_SCRATCH && d[26] == 0x42 && d[27] == 1 && d[28] == 3 &&
                     d[29] == 0x43 && d[30] == 32);
        if (!policy_ok) { s->last_sw = 0x6A80; return SCP03_E_SW; }
        sc_exists = 1; sc_owner = OWN_G0; memcpy(se_slot, d + 31, 32); s->last_sw = 0x9000; return 0;
    }
    s->last_sw = 0x6D00; return SCP03_E_SW;
}
int scp03_ec_write_priv(scp03_session_t *s, uint32_t obj, const uint8_t priv[32]) {
    s->nxfer++;
    if (!s->authed || dead(s)) { s->last_sw = 0; return SCP03_E_RMAC; }
    if (obj != SE_OBJ_PK_SCRATCH) { s->last_sw = 0x6986; return SCP03_E_SW; }
    int n = writes++;
    if (!sc_exists) { s->last_sw = 0x6A82; return SCP03_E_SW; }
    if (n == fail_write_n || (fail_write_from >= 0 && n >= fail_write_from)) { s->last_sw = 0x6A80; return SCP03_E_SW; }
    memcpy(se_slot, priv, 32); if (hist_n < 8) memcpy(hist[hist_n++], priv, 32);
    if (n == badmac_write_n) { s->stage = 99; s->last_sw = 0x9000; return SCP03_E_RMAC; }   /* applied, but the answer fails its MAC */
    s->last_sw = 0x9000; return 0;
}
static int rng(void *p, unsigned char *o, size_t n) { (void)p; for (size_t i = 0; i < n; i++) o[i] = (uint8_t)rand(); return 0; }
static size_t der_int(uint8_t *o, const uint8_t v[32]) {
    int i = 0; while (i < 31 && v[i] == 0) i++;
    int pad = v[i] & 0x80; size_t l = (size_t)(32 - i) + (pad ? 1 : 0);
    o[0] = 0x02; o[1] = (uint8_t)l; size_t p = 2; if (pad) o[p++] = 0;
    memcpy(o + p, v + i, 32 - i); return p + 32 - i;
}
int scp03_ec_sign(scp03_session_t *s, uint32_t obj, const uint8_t hash[32], uint8_t *der, size_t dcap, size_t *dlen) {
    s->nxfer++; signs++;
    if (!s->authed || dead(s)) { s->last_sw = 0; return SCP03_E_RMAC; }
    if (obj != SE_OBJ_PK_SCRATCH || fail_sign || !sc_exists) { s->last_sw = 0x6985; return SCP03_E_SW; }
    mbedtls_mpi d, r, sg; mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&sg);
    mbedtls_mpi_read_binary(&d, se_slot, 32);
    mbedtls_ecdsa_sign(&G, &r, &sg, &d, hash, 32, rng, NULL);
    uint8_t rb[32], sb[32], body[80]; mbedtls_mpi_write_binary(&r, rb, 32); mbedtls_mpi_write_binary(&sg, sb, 32);
    size_t p = 2; p += der_int(body + p, rb); p += der_int(body + p, sb); body[0] = 0x30; body[1] = (uint8_t)(p - 2);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&sg);
    if (p > dcap) return SCP03_E_SIZE;
    memcpy(der, body, p); *dlen = p; s->last_sw = 0x9000; return 0;
}

#include "pk_glue.inc"
/* v19: what the ESP32's passkey session writes on PKM_IN: inner || tag */
static void give_pkm(void) { memcpy(g_pkm_in, se_master_blob, 32); memcpy(g_pkm_in + 32, se_master_tag, 32); g_pkm_valid = master_ok; }
#include "pk_vectors.h"
#include "pkrecover.inc"   /* the same file the ESP32 builds (e3b/src/pkrecover.inc) */

static int pk_fetch_master(uint8_t spk[32]) {   /* test helper: one session, fetch, close */
    scp03_session_t s; uint16_t sw; if (pk_open(&s)) return -1;
    int rc = pk_fetch_master_in(&s, spk, &sw); scp03_close(&s); return rc;
}
static int pass, fail;
#define CHECK(c, m) do { if (c) { pass++; printf("PASS  %s\n", m); } else { fail++; printf("FAIL  %s\n", m); } } while (0)

static void reset_counts(void) { writes = signs = opens = closes = fetches = deletes = creates = 0; fail_open = fail_sign = fail_create = 0; fail_write_n = fail_write_from = badmac_write_n = -1; hist_n = 0; }
static void put_in(uint8_t op, const uint8_t nonce[16], const uint8_t tag[16], const uint8_t rp[32], const uint8_t h[32]) {
    memset(g_pk_in, 0, PK_IN_LEN); g_pk_in[0] = op;
    if (nonce) memcpy(g_pk_in + 1, nonce, 16);
    if (tag) memcpy(g_pk_in + 17, tag, 16);
    if (rp) memcpy(g_pk_in + 33, rp, 32);
    if (h) memcpy(g_pk_in + 65, h, 32);
    g_pk_in_valid = 1;
}
static int der_to_raw(const uint8_t *d, size_t n, uint8_t raw[64]) {
    if (n < 8 || d[0] != 0x30) return 0;
    size_t p = 2; memset(raw, 0, 64);
    for (int i = 0; i < 2; i++) {
        if (d[p] != 0x02) return 0;
        size_t l = d[p + 1]; p += 2;
        const uint8_t *v = d + p; size_t vl = l; while (vl > 32 && *v == 0) { v++; vl--; }
        if (vl > 32) return 0;
        memcpy(raw + i * 32 + (32 - vl), v, vl); p += l;
    }
    return 1;
}
static void pub_of(const uint8_t k[32], uint8_t pub[65]) {
    mbedtls_mpi d; mbedtls_ecp_point Q; mbedtls_mpi_init(&d); mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_read_binary(&d, k, 32); mbedtls_ecp_mul(&G, &Q, &d, &G.G, rng, NULL);
    size_t ol; mbedtls_ecp_point_write_binary(&G, &Q, 0, &ol, pub, 65);
    mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&Q);
}
static int verify(const uint8_t pub[65], const uint8_t h[32], const uint8_t raw[64]) {
    mbedtls_ecp_point Q; mbedtls_mpi r, s; mbedtls_ecp_point_init(&Q); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_ecp_point_read_binary(&G, &Q, pub, 65); mbedtls_mpi_read_binary(&r, raw, 32); mbedtls_mpi_read_binary(&s, raw + 32, 32);
    int ok = mbedtls_ecdsa_verify(&G, h, 32, &Q, &r, &s) == 0;
    mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s); return ok;
}
static int allzero(const uint8_t *p, size_t n) { uint8_t a = 0; while (n--) a |= *p++; return a == 0; }
static int sw_of(const uint8_t *b) { return (b[8] << 8) | b[9]; }
/* Seal a master through the REAL PKMASTER and "store" it in the fake SE. */
static int seal_master(const uint8_t spk[32]) {
    memcpy(g_hash_in, spk, 32); g_hash_in_valid = 1;
    int rc = do_pkmaster(); g_hash_in_valid = 0;
    if (rc == 0) { memcpy(se_master_blob, g_sig_out, 32); memcpy(se_master_tag, g_sig_out + 32, 32); master_ok = 1; give_pkm(); }
    return rc;
}

int main(void) {
    srand(42); mbedtls_ecp_group_init(&G); mbedtls_ecp_group_load(&G, MBEDTLS_ECP_DP_SECP256R1);
    for (int i = 0; i < 32; i++) g_kg0[i] = (uint8_t)(0x5A ^ i);
    v3_value(fake_pcr);   /* a passkey window is open unless a check says otherwise */
    printf("restorable passkeys G0 host test (pk_glue.inc, G0 v16: signed in the G0)\n");

    /* KATs against Python */
    { uint8_t t[16], k[32];
      pk_tag(KAT_SPK, KAT_NONCE, KAT_RP, t);
      CHECK(!memcmp(t, KAT_TAG, 16), "KAT: ID tag matches the Python vector");
      CHECK(pk_derive(KAT_SPK, KAT_NONCE, KAT_RP, k) == 0 && !memcmp(k, KAT_K, 32), "KAT: per-site key k matches the Python vector");
      uint8_t m[32]; hmac_sha256(KAT_SEED, 64, (const uint8_t *)"FAVILLA-PASSKEY-MASTER-v1", 25, m);
      CHECK(!memcmp(m, KAT_MASTER, 32), "KAT: S_pk = HMAC(seed, \"FAVILLA-PASSKEY-MASTER-v1\") matches Python (the ESP32 computes this at onboarding)"); }
    { uint8_t z[32] = {0}, one[32] = {0}, nm1[32], n[32], np1[32], ff[32];
      one[31] = 1; memcpy(n, PK_P256_N, 32); memcpy(nm1, n, 32); nm1[31]--; memcpy(np1, n, 32); np1[31]++; memset(ff, 0xFF, 32);
      CHECK(!pk_scalar_ok(z) && pk_scalar_ok(one) && pk_scalar_ok(nm1) && !pk_scalar_ok(n) && !pk_scalar_ok(np1) && !pk_scalar_ok(ff),
            "scalar range: 0, n, n+1, FF..FF refused; 1 and n-1 accepted"); }
    { uint8_t h[32], e[32]; pk_recover_hash(1, h); sha256((const uint8_t *)"FAVILLA-PK-RECOVER-1", 20, e);
      int a = !memcmp(h, e, 32); pk_recover_hash(2, h); sha256((const uint8_t *)"FAVILLA-PK-RECOVER-2", 20, e);
      CHECK(a && !memcmp(h, e, 32), "recovery hashes = SHA256(\"FAVILLA-PK-RECOVER-1\"/\"-2\"), as proven on silicon in 2e"); }

    /* PKMASTER */
    CHECK(seal_master(KAT_SPK) == 0, "PKMASTER seals in the onboarding seal window");
    { uint8_t t[32]; pk_master_tag(g_sig_out, t);
      CHECK(!memcmp(t, g_sig_out + 32, 32) && !allzero(g_sig_out + 32, 32), "v19: PKMASTER returns inner || tag, tag = HMAC(K_G0, label || inner)"); }
    { uint8_t got[32]; CHECK(pk_fetch_master(got) == 0 && !memcmp(got, KAT_SPK, 32), "master read back inside the PKSIGN session = S_pk (master IV)"); }
    CHECK(seal_master(KAT_SPK) != 0, "PKMASTER a second time in the same window: refused");
    g_pk_master_done = 0; g_seal_window = 0;
    CHECK(seal_master(KAT_SPK) != 0, "PKMASTER outside the seal window: refused (a running ESP32 cannot plant a master)");
    g_seal_window = 1; g_pk_master_done = 0; seal_master(KAT_SPK); g_seal_window = 0;
    { uint8_t blob[32], x[32] = {7}, got[32]; kg0_seal(x, blob);   /* what PROVISION hands out: the SCALAR IV */
      memcpy(g_pkm_in, blob, 32); g_pkm_valid = 1;                  /* with the real master's tag, or a made-up one */
      CHECK(pk_fetch_master(got) != 0, "v19: a PROVISION blob handed in as the master: refused (its tag does not check)");
      give_pkm(); }

    /* v19: the passkey master opens only from the passkey session, in a window */
    { uint8_t got[32];
      CHECK(pk_fetch_master(got) == 0 && !memcmp(got, KAT_SPK, 32), "v19: PKM_IN with the right tag at V_3, PASSKEY life: S_pk");
      CHECK(master_obj_touched == 0, "v19: the G0 never asks the SE for K_PK, PK_MASTER_P, K_PKN or PK_MASTER");
      g_pkm_in[40] ^= 1; CHECK(pk_fetch_master(got) != 0, "v19: a flipped tag byte: refused"); give_pkm();
      g_pkm_in[3] ^= 1; CHECK(pk_fetch_master(got) != 0, "v19: a flipped inner byte (tag no longer matches): refused"); give_pkm();
      g_pkm_valid = 0; CHECK(pk_fetch_master(got) != 0, "v19: no PKM_IN: refused"); give_pkm();
      fake_pcr[0] ^= 1; CHECK(pk_fetch_master(got) != 0, "v19: latch not at V_3 (the window was burned): the kept 64 bytes are useless"); v3_value(fake_pcr);
      pcr_fail = 1; CHECK(pk_fetch_master(got) != 0, "v19: latch not readable: refused"); pcr_fail = 0;
      g_door = DOOR_NOSTR; CHECK(pk_fetch_master(got) != 0, "v19: NOSTR life: refused (no NOSTR copy any more)");
      g_door = DOOR_UNSET; CHECK(pk_fetch_master(got) != 0, "v19: UNSET life: refused");
      g_door = DOOR_BTC;   CHECK(pk_fetch_master(got) != 0, "v19: BTC life: refused"); g_door = DOOR_PASSKEY;
      CHECK(pk_fetch_master(got) == 0 && !memcmp(got, KAT_SPK, 32), "v19: back in the window: S_pk again"); }

    uint8_t rp[32]; memcpy(rp, KAT_RP, 32);
    uint8_t nonce[16], tag[16], pub[65];

    /* v16 (7 Nov 2026): the G0 signs; the SE051 only gives the master. */
    reset_counts(); put_in(PK_OP_REGISTER, NULL, NULL, rp, NULL); do_pksign();
    CHECK(g_btc_out[5] == 0 && g_btc_out[4] == 2 && g_pk_kat == 1, "v16: REGISTER ok, and the G0's P-256 known-answer test (RFC 6979 A.2.5) passed first");
    CHECK(writes == 0 && signs == 0 && deletes == 0 && creates == 0, "v16: REGISTER writes nothing to the SE and asks it to sign nothing (the site key never reaches the SE051)");
    memcpy(nonce, g_btc_out + 12, 16); memcpy(tag, g_btc_out + 28, 16);
    { uint8_t t[16]; pk_tag(KAT_SPK, nonce, rp, t); CHECK(!memcmp(t, tag, 16) && !allzero(nonce, 16), "REGISTER: a fresh nonce and its tag for this site"); }
    { uint8_t k[32], kp[65], s1[64], s2[64], h1[32], h2[32];
      pk_derive(KAT_SPK, nonce, rp, k); pub_of(k, kp);
      pk_recover_hash(1, h1); pk_recover_hash(2, h2);
      int ok = der_to_raw(g_btc_out + 45, g_btc_out[44], s1) && der_to_raw(g_btc_out + 118, g_btc_out[117], s2) &&
               pkrecover_p256_pair(h1, s1, h2, s2, pub);
      CHECK(ok && !memcmp(pub, kp, 65), "REGISTER: the public key recovered from the two signatures is k*G (the ESP32's recovery is unchanged)");
      CHECK(fetches == 1 && opens == 1 && sessions_live == 0, "REGISTER: ONE SE session, for the master only; closed before signing"); }
    { const int left = g_pk_sign_left; reset_counts(); put_in(PK_OP_REGISTER, NULL, NULL, rp, NULL); do_pksign();
      CHECK(g_btc_out[5] == 0 && memcmp(nonce, g_btc_out + 12, 16) != 0 && g_pk_sign_left == left - 1, "second REGISTER: a different credential, one signature from the budget"); }

    { uint8_t h[32], raw[64], raw2[64]; for (int i = 0; i < 32; i++) h[i] = (uint8_t)(i * 7);
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == 0 && der_to_raw(g_btc_out + 45, g_btc_out[44], raw) && verify(pub, h, raw),
            "SIGN: signature over the given hash verifies under the registered public key");
      CHECK(allzero(g_btc_out + 12, 32) && g_btc_out[117] == 0 && writes == 0 && signs == 0, "SIGN: no nonce/tag/second signature out; nothing written to the SE");
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == 0 && der_to_raw(g_btc_out + 45, g_btc_out[44], raw2) && verify(pub, h, raw2) && memcmp(raw, raw2, 32) != 0,
            "v18 SIGN: hedged: the same request twice gives two different r, both verify (no repeated nonce for a fault attack)"); }

    { uint8_t rp2[32]; memcpy(rp2, rp, 32); rp2[0] ^= 1; uint8_t h[32] = {1};
      const int left = g_pk_sign_left;
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp2, h); do_pksign();
      CHECK(g_btc_out[5] == PK_E_TAG && sessions_live == 0 && allzero(g_btc_out + 12, BTC_OUT_LEN - 12) && g_pk_sign_left == left,
            "SIGN for another site with this ID: PK_E_TAG, session closed, no output, budget not charged");
      uint8_t t2[16]; memcpy(t2, tag, 16); t2[15] ^= 0x80;
      reset_counts(); put_in(PK_OP_SIGN, nonce, t2, rp, h); do_pksign();
      CHECK(g_btc_out[5] == PK_E_TAG, "SIGN with a forged tag: PK_E_TAG");
      uint8_t n2[16]; memcpy(n2, nonce, 16); n2[0] ^= 1;
      reset_counts(); put_in(PK_OP_SIGN, n2, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == PK_E_TAG, "SIGN with a changed nonce: PK_E_TAG"); }

    { uint8_t h[32] = {2};
      reset_counts(); g_pk_in_valid = 0; do_pksign();
      CHECK(g_btc_out[5] == PK_E_INPUT && fetches == 0, "no PK_IN: PK_E_INPUT, no master fetch");
      reset_counts(); put_in(7, NULL, NULL, rp, h); do_pksign();
      CHECK(g_btc_out[5] == PK_E_INPUT && fetches == 0, "unknown op: PK_E_INPUT");
      reset_counts(); g_keys_valid = 0; put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign(); g_keys_valid = 1;
      CHECK(g_btc_out[5] == PK_E_KEYS && fetches == 0, "no keys: PK_E_KEYS");
      reset_counts(); g_door1_locked = 0; put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign(); g_door1_locked = 1;
      CHECK(g_btc_out[5] == PK_E_KEYS && fetches == 0 && opens == 0, "no Door-1 boot lock this life: PK_E_KEYS, no session");
      reset_counts(); master_ok = 0; give_pkm(); put_in(PK_OP_REGISTER, NULL, NULL, rp, NULL); do_pksign(); master_ok = 1; give_pkm();
      CHECK(g_btc_out[5] == PK_E_MASTER && sessions_live == 0, "v19: no master from the passkey session: PK_E_MASTER, session closed");
      reset_counts(); pcr_fail = 1; put_in(PK_OP_REGISTER, NULL, NULL, rp, NULL); do_pksign(); pcr_fail = 0;
      CHECK(g_btc_out[5] == PK_E_MASTER && sessions_live == 0 && sw_of(g_btc_out) == 0x6985, "v19: latch read refused: PK_E_MASTER with the SE's SW, session closed");
      reset_counts(); fail_open = 1; put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == PK_E_OPEN && sessions_live == 0 && sw_of(g_btc_out) == 0x6982, "session refused: PK_E_OPEN with the open's SW"); }

    /* v16: the PKSIGN budget, refilled with the vault's (C+) */
    { uint8_t h[32] = {4};
      g_pk_sign_left = 2; g_vlt_refills = 0;
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == 0 && g_pk_sign_left == 0, "budget: the last two signatures of a sitting work");
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == PK_E_BUDGET && fetches == 0 && opens == 0 && allzero(g_btc_out + 12, BTC_OUT_LEN - 12), "budget spent: PK_E_BUDGET before any session, no output");
      vlt_refill();
      CHECK(g_pk_sign_left == PK_PER_SITTING && g_vlt_refills == 1, "a PIN entered on the KEY (the vault refill) refills the PKSIGN budget too, and counts one refill");
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == 0, "after the refill: signs again");
      g_pk_sign_left = 0; g_vlt_refills = VLT_REFILLS_MAX; vlt_refill();
      CHECK(g_pk_sign_left == 0, "refills used up for this life: the budget stays empty (power cycle)");
      g_vlt_refills = 0; g_pk_sign_left = PK_PER_SITTING; }

    /* v16: a failed known-answer test stops all signing this life */
    { uint8_t h[32] = {5};
      g_pk_kat = -1;
      reset_counts(); put_in(PK_OP_SIGN, nonce, tag, rp, h); do_pksign();
      CHECK(g_btc_out[5] == PK_E_KAT && fetches == 0, "KAT failed this life: PK_E_KAT, the master is not even read");
      g_pk_kat = 0; }

    /* PKSCRUB still clears what a v15 G0 may have left in the scratch object */
    { g_pk_scratch_own = 0; sc_exists = 1; sc_owner = OWN_ROGUE_NODEL;
      reset_counts(); do_pkscrub();
      CHECK(g_sig_out[5] == PK_E_SCRATCH && writes == 0, "PKSCRUB on a planted object: PK_E_SCRATCH, nothing written");
      sc_owner = OWN_ROGUE_DEL;
      reset_counts(); do_pkscrub();
      CHECK(g_sig_out[5] == 0 && deletes == 1 && creates == 1 && sc_owner == OWN_G0, "PKSCRUB: a deletable leftover is replaced by the G0's own, junk inside");
      g_pk_scratch_own = 0; sc_exists = 0;
      reset_counts(); do_pkscrub();
      CHECK(g_sig_out[5] == 0 && creates == 1 && g_pk_scratch_own, "PKSCRUB claims the scratch object when nothing is there");
      reset_counts(); g_keys_valid = 0; do_pkscrub(); g_keys_valid = 1;
      CHECK(g_sig_out[5] == PK_E_KEYS && opens == 0, "PKSCRUB with no keys: PK_E_KEYS"); }

    { int ok = 0;
      for (int it = 0; it < 200; it++) {
        uint8_t r[32], h[32], s1[64], s2[64], h1[32], h2[32], pb[65], raw[64], nn[16], tg[16], m[32];
        for (int i = 0; i < 32; i++) { r[i] = (uint8_t)rand(); h[i] = (uint8_t)rand(); m[i] = (uint8_t)rand(); }
        g_seal_window = 1; g_pk_master_done = 0; seal_master(m); g_seal_window = 0;
        g_pk_sign_left = PK_PER_SITTING;
        put_in(PK_OP_REGISTER, NULL, NULL, r, NULL); do_pksign();
        if (g_btc_out[5]) continue;
        memcpy(nn, g_btc_out + 12, 16); memcpy(tg, g_btc_out + 28, 16);
        pk_recover_hash(1, h1); pk_recover_hash(2, h2);
        if (!der_to_raw(g_btc_out + 45, g_btc_out[44], s1) || !der_to_raw(g_btc_out + 118, g_btc_out[117], s2) || !pkrecover_p256_pair(h1, s1, h2, s2, pb)) continue;
        put_in(PK_OP_SIGN, nn, tg, r, h); do_pksign();
        if (g_btc_out[5] || !der_to_raw(g_btc_out + 45, g_btc_out[44], raw) || !verify(pb, h, raw)) continue;
        ok++;
      }
      CHECK(ok == 200, "200 random masters and sites: seal -> register -> recover -> sign -> verify, all good"); }

    /* user verification check (31 Oct 2026) */
    { uint8_t pin[32] = {0}, bad[32] = {0}; memcpy(pin, "482915", 6); memcpy(bad, "482916", 6);
      #define UVIN(x) do { memcpy(g_hash_in, x, 32); g_hash_in_valid = 1; } while (0)
      uv_clear(); UVIN(pin); do_uvcheck();
      CHECK(!memcmp(g_sig_out, "UVCK", 4) && g_sig_out[5] == 0xE1, "UVCHECK before UVSET: 0xE1 (no reference)");
      UVIN(pin); do_uvset(); CHECK(g_sig_out[5] == 0 && g_sig_out[6] == 3 && g_uv_set, "UVSET: reference kept, 3 tries");
      { uint8_t want[32]; uv_ref_of(pin, want); CHECK(!memcmp(want, g_uv_ref, 32) && memcmp(g_uv_ref, pin, 32) != 0, "the reference is HMAC(K_G0, label || pin), not the PIN"); }
      UVIN(pin); do_uvcheck(); CHECK(g_sig_out[5] == 0 && g_sig_out[6] == 3, "UVCHECK right: ok, tries stay 3");
      UVIN(bad); do_uvcheck(); CHECK(g_sig_out[5] == 0xE2 && g_sig_out[6] == 2, "UVCHECK wrong: 0xE2, 2 left");
      UVIN(pin); do_uvcheck(); CHECK(g_sig_out[5] == 0 && g_sig_out[6] == 3, "a right PIN gives the tries back");
      UVIN(bad); do_uvcheck(); UVIN(bad); do_uvcheck(); UVIN(bad); do_uvcheck();
      CHECK(g_sig_out[5] == 0xE2 && g_sig_out[6] == 0 && !g_uv_set && allzero(g_uv_ref, 32), "3 wrong in a row: reference wiped");
      UVIN(pin); do_uvcheck(); CHECK(g_sig_out[5] == 0xE1, "after 3 wrong even the right PIN is refused until the next UVSET");
      UVIN(pin); do_uvset(); do_uvclear(); CHECK(!g_uv_set && allzero(g_uv_ref, 32), "UVCLEAR wipes the reference");
      g_keys_valid = 0; UVIN(pin); do_uvset(); CHECK(g_sig_out[5] == 0xE3 && !g_uv_set, "no keys: UVSET refused"); g_keys_valid = 1;
      #undef UVIN
    }

    CHECK(master_obj_touched == 0, "v19: over the whole run the G0 never touched K_PK, PK_MASTER_P, K_PKN or PK_MASTER");
    printf("\npk glue: %d/%d passed\n", pass, pass + fail);
    return fail != 0;
}
