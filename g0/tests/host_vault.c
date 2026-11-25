/* Vault records host test (2 Nov 2026). Fake SE copied from host_pk.c. Runs the REAL
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
#include "totp.h"
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
static uint8_t g_door = DOOR_PASSKEY;   /* v19: VAULT runs only in a PASSKEY life */
#define VLT_REFILLS_MAX 4u
static uint8_t g_vlt_refills = 0; static int life_saves = 0;
#define VLT_LABEL_PER_LIFE 800u
static uint16_t g_lbl_used = 0; static uint8_t g_imp_used = 0;   /* v15: main.c, life token word 2 */
static void life_save(void) { life_saves++; }
/* v24: the vault limit's flash log (key_store.c), faked */
static int host_lim_stored = -1, host_lim_fail = 0, host_lim_writes = 0;
static int ks_lim_store(uint8_t l) { if (host_lim_fail) return 0; host_lim_stored = l; host_lim_writes++; return 1; }
static int daily_used = 0;   /* the daily wrap key must never be asked for any more (S3) */
static void secure_wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }
static void entropy_mix(const uint8_t *d, size_t n) {
    static uint32_t ctr; sha256_ctx c; sha256_init(&c);
    sha256_update(&c, g_pool, 32); if (d && n) sha256_update(&c, d, n);
    ctr++; sha256_update(&c, (uint8_t *)&ctr, 4); sha256_final(&c, g_pool);
}
#include "hedge.inc"   /* v18: the firmware's own hedge32 (pk_glue.inc uses it) */
static void host_challenge(uint8_t hc[8]) { uint8_t h[32]; entropy_mix((const uint8_t *)"hc", 2); sha256(g_pool, 32, h); memcpy(hc, h, 8); }
static int relay_xfer(void *c, const uint8_t *a, size_t al, uint8_t *r, size_t rc, size_t *rl) { (void)c;(void)a;(void)al;(void)r;(void)rc;(void)rl; return -1; }
#include "extracted_pk.inc"   /* REAL kg0_iv + kg0_seal from main.c */

/* ---- fake SE ---- */
#ifdef HOST_VPUB
static uint8_t vpub_blob[48]; static int vpub_ok = 0;   /* v14: SE_OBJ_VPUB */
#endif
static mbedtls_ecp_group G;
enum { OWN_NONE, OWN_G0, OWN_ROGUE_NODEL, OWN_ROGUE_DEL };
static int sc_exists = 0, sc_owner = OWN_NONE; static uint8_t se_slot[32];
static uint8_t se_master_blob[32], se_master_tag[32]; static int master_ok = 0; static int master_obj_touched = 0;
static int fail_open, fail_write_n = -1, fail_write_from = -1, badmac_write_n = -1, fail_sign, fail_create;
static int writes, signs, opens, closes, fetches, deletes, creates, sessions_live, policy_ok;
static uint8_t hist[8][32]; static int hist_n;

/* The master object: ReadObject gives IV16 || CT32 of the SE's daily-wrap layer;
 * here that layer is the identity (CipherOneShot returns its input), so CT32 is
 * the G0's K_G0 layer exactly as PKMASTER made it. Readable only to the G0's
 * session while the Door-1 PCR is unlocked (modelled by g_door1_locked). */
int scp03_read_object(scp03_session_t *s, uint32_t obj, uint8_t *out, size_t ocap, size_t *olen) {
    s->nxfer++; fetches++;
    if (!s->authed || s->stage == 99) { s->last_sw = 0; return SCP03_E_RMAC; }
#ifdef HOST_VPUB
    if (obj == SE_OBJ_VPUB) {   /* G0 READ; the K_PKN layer is the identity here, as for the master */
        if (!vpub_ok) { s->last_sw = 0x6985; return SCP03_E_SW; }
        memcpy(out, vpub_blob, 48); *olen = 48; s->last_sw = 0x9000; return 0;
    }
#endif
    (void)ocap;
    if (obj == SE_OBJ_PK_MASTER_P || obj == SE_OBJ_PK_MASTER) master_obj_touched++;   /* v19: no G0 right on them */
    s->last_sw = 0x6986; return SCP03_E_SW;
}
int scp03_cipher_oneshot(scp03_session_t *s, uint32_t key_obj, int decrypt, const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]) {
    (void)iv; s->nxfer++;
    if (key_obj == SE_OBJ_K_PK || key_obj == SE_OBJ_K_PKN) { master_obj_touched++; s->last_sw = 0x6986; return SCP03_E_SW; }
    if (!s->authed || key_obj != SE_OBJ_AES_WRAP_DAILY || !decrypt) { s->last_sw = 0x6985; return SCP03_E_SW; }
    daily_used++;   /* v19: only VSIGN's VPUB copy is under the daily layer (the identity here) */
    memcpy(out, in, 32); s->last_sw = 0x9000; return 0;
}
/* The latch read the G0 does in its own session (main.c). V_3 while a passkey window is open. */
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


#ifdef HOST_VPUB
/* v14: the slice of main.c that vpub_glue.inc uses (real libsecp256k1 + antiexfil.c) */
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_preallocated.h"
#include "antiexfil.h"
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;printf("ILLEGAL: %s\n",m);}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;printf("ERROR: %s\n",m);}
static secp256k1_context *g_ctx; static uint8_t g_ctx_buf[512] __attribute__((aligned(16)));
static uint32_t HAL_GetTick(void) { return 1000; }
#define AE_IN_LEN 64
static uint8_t g_ae_in[AE_IN_LEN]; static int g_ae_in_valid = 0;
typedef struct { uint8_t kind, key[32], k0[32], r0[33], h[32], msg[32], pub33[33], btc_kind, vault; uint32_t t0; } ae_pending_t;
static ae_pending_t g_ae;
static void ae_wipe(void) { memset(&g_ae, 0, sizeof(g_ae)); }
#endif
#include "pk_glue.inc"
#include "vault_glue.inc"
#ifndef HOST_VPUB
/* v14: PUBSEAL needs libsecp256k1; built with -DHOST_VPUB (run_vault_test.sh, second build) it is the real one. */
static int vlt_pubseal(const uint8_t kv[32], uint8_t out72[72]) { (void)kv; (void)out72; return -1; }
#else
#include "vpub_glue.inc"
#endif
#include "mbedtls/md.h"
#include "mbedtls/aes.h"

static int pass, fail;
#define CHECK(c, m) do { if (c) { pass++; printf("PASS  %s\n", m); } else { fail++; printf("FAIL  %s\n", m); } } while (0)

/* v19: what the ESP32's passkey session writes on PKM_IN before each VAULT op */
static void give_pkm(void) { memcpy(g_pkm_in, se_master_blob, 32); memcpy(g_pkm_in + 32, se_master_tag, 32); g_pkm_valid = master_ok; }
static int seal_master(const uint8_t spk[32]) {
    g_seal_window = 1; g_pk_master_done = 0;
    memcpy(g_hash_in, spk, 32); g_hash_in_valid = 1;
    int rc = do_pkmaster(); g_hash_in_valid = 0; g_seal_window = 0;
    if (rc == 0) { memcpy(se_master_blob, g_sig_out, 32); memcpy(se_master_tag, g_sig_out + 32, 32); master_ok = 1; give_pkm(); }
    return rc;
}
/* independent reference (mbedtls, not the G0's sha256 / tinyaes) */
static void ref_hmac(const uint8_t *k, size_t kl, const uint8_t *m, size_t ml, uint8_t out[32]) {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, kl, m, ml, out);
}
static void ref_keys(const uint8_t spk[32], uint8_t kv[32], uint8_t ke[32], uint8_t km[32]) {
    ref_hmac(spk, 32, (const uint8_t *)"FAVILLA-VAULT-v1", 16, kv);
    ref_hmac(kv, 32, (const uint8_t *)"ENC", 3, ke);
    ref_hmac(kv, 32, (const uint8_t *)"MAC", 3, km);
}
static void ref_tag(const uint8_t kv[32], const uint8_t *site, size_t n, uint8_t t[8]) {
    uint8_t m[300], h[32]; memcpy(m, "SITE", 4); memcpy(m + 4, site, n); ref_hmac(kv, 32, m, 4 + n, h); memcpy(t, h, 8);
}
static void put(uint8_t op, const uint8_t *d, size_t n) {
    memset(g_vlt_in, 0, VLT_IN_LEN); g_vlt_in[0] = op; g_vlt_in[1] = (uint8_t)(n >> 8); g_vlt_in[2] = (uint8_t)n;
    if (n) { memcpy(g_vlt_in + 3, d, n); }
    g_vlt_in_valid = 1;
}
static uint8_t run(uint8_t op, const uint8_t *d, size_t n, uint8_t *out, size_t *on) {
    put(op, d, n); do_vault(); g_vlt_in_valid = 0;
    size_t l = ((size_t)g_vlt_out[8] << 8) | g_vlt_out[9];
    if (out) memcpy(out, g_vlt_out + 12, l);
    if (on) *on = l;
    return g_vlt_out[5];
}
static size_t mk_pt(uint8_t *pt, const char *site, size_t extra, uint8_t fill) {
    size_t sl = strlen(site); pt[0] = (uint8_t)sl; memcpy(pt + 1, site, sl);
    for (size_t i = 0; i < extra; i++) pt[1 + sl + i] = (uint8_t)(fill + i);
    return 1 + sl + extra;
}
static size_t mk_seal_in(uint8_t *in, const uint8_t hdr[13], const uint8_t *pt, size_t ptn) { memcpy(in, hdr, 13); memcpy(in + 13, pt, ptn); return 13 + ptn; }

int main(void) {
    srand(7); mbedtls_ecp_group_init(&G); mbedtls_ecp_group_load(&G, MBEDTLS_ECP_DP_SECP256R1);
    for (int i = 0; i < 32; i++) g_kg0[i] = (uint8_t)(0x5A ^ i);
    v3_value(fake_pcr); (void)pcr_fail;   /* v19: a passkey window is open unless a check says otherwise */
    printf("vault records G0 host test (vault_glue.inc)\n");
    /* v24: the default is no limit; sections 1 to 14 run as an owner who chose 32 (what was fixed before v24) */
    CHECK(g_vlt_limit == 0 && g_vlt_limit_next == 0, "v24: the vault limit starts at none (the default)");
    g_vlt_limit = g_vlt_limit_next = VLT_PER_SITTING; g_vlt_open_left = g_vlt_tag_left = VLT_PER_SITTING;
    uint8_t spk[32]; for (int i = 0; i < 32; i++) spk[i] = (uint8_t)(0xA0 + i);
    seal_master(spk);
    uint8_t kv[32], ke[32], km[32]; ref_keys(spk, kv, ke, km);
    uint8_t hdr[13] = {1,2,3,4,5,6,7,8, 0,0,0,42, 1};
    uint8_t pt[512], in[600], sealed[600], out[600]; size_t ptn, sn, on;
    uint8_t s1x[600]; size_t n2x = 0;   /* v15 LABEL test */

    /* 1. SEAL, checked against an independent implementation */
    ptn = mk_pt(pt, "webauthn.io", 60, 0x30);
    uint8_t left0 = g_vlt_open_left;
    CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), sealed, &sn) == 0, "SEAL ok");
    CHECK(sessions_live == 0, "SEAL: the SE session is closed afterwards");
    { size_t ct = sn - VLT_OVER; uint8_t mac[32], tag[8], dec[512];
      ref_hmac(km, 32, sealed, sn - 32, mac); ref_tag(kv, (const uint8_t *)"webauthn.io", 11, tag);
      mbedtls_aes_context a; mbedtls_aes_init(&a); mbedtls_aes_setkey_dec(&a, ke, 256);
      uint8_t iv[16]; memcpy(iv, sealed + 21, 16);
      mbedtls_aes_crypt_cbc(&a, MBEDTLS_AES_DECRYPT, ct, iv, sealed + 37, dec); mbedtls_aes_free(&a);
      uint8_t pad = dec[ct - 1];
      CHECK(!memcmp(sealed, hdr, 13), "SEAL: header copied in the clear");
      CHECK(!memcmp(sealed + 13, tag, 8), "SEAL: site tag = HMAC(K_vault, \"SITE\" || site)[0:8] (mbedtls reference)");
      CHECK(!memcmp(sealed + sn - 32, mac, 32), "SEAL: MAC = HMAC(K_mac, hdr || tag || iv || ct) (mbedtls reference)");
      CHECK(ct % 16 == 0 && pad >= 1 && pad <= 16 && ct - pad == ptn && !memcmp(dec, pt, ptn), "SEAL: AES-256-CBC + PKCS#7 decrypts to the plaintext (mbedtls reference)");
      CHECK(g_vlt_open_left == left0, "SEAL uses no OPEN"); }

    /* 2. OPEN */
    CHECK(run(VLT_OP_OPEN, sealed, sn, out, &on) == 0 && on == 13 + ptn && !memcmp(out, hdr, 13) && !memcmp(out + 13, pt, ptn), "OPEN gives back header and plaintext");
    CHECK(g_vlt_open_left == left0 - 1 && g_vlt_out[7] == left0 - 1, "OPEN uses one of the budget, and the diag shows what is left");
    CHECK(sessions_live == 0, "OPEN: the SE session is closed afterwards");

    /* 3. TAG */
    { uint8_t t[8]; size_t tn; uint8_t l = g_vlt_open_left;
      CHECK(run(VLT_OP_TAG, (const uint8_t *)"webauthn.io", 11, t, &tn) == 0 && tn == 8 && !memcmp(t, sealed + 13, 8), "TAG(site) equals the tag SEAL put on that site's record");
      CHECK(g_vlt_open_left == l, "TAG uses no OPEN");
      uint8_t t2[8]; run(VLT_OP_TAG, (const uint8_t *)"webauthn.iO", 11, t2, NULL);
      CHECK(memcmp(t, t2, 8) != 0, "TAG differs for a different site"); }

    /* 4. tampering: one bit anywhere fails, and costs nothing */
    { int allbad = 1, nobudget = 1, noout = 1;
      for (size_t i = 0; i < sn; i++) for (int b = 0; b < 8; b += 7) {
        uint8_t t[600]; memcpy(t, sealed, sn); t[i] ^= (uint8_t)(1 << b);
        uint8_t l = g_vlt_open_left;
        if (run(VLT_OP_OPEN, t, sn, out, &on) != VLT_E_AUTH) allbad = 0;
        if (g_vlt_open_left != l) nobudget = 0;
        if (on != 0 || g_vlt_out[12] != 0) noout = 0;
      }
      CHECK(allbad, "OPEN: a flipped bit in header, tag, IV, ciphertext or MAC is refused (VLT_E_AUTH)");
      CHECK(nobudget, "OPEN: a refused record costs no budget");
      CHECK(noout, "OPEN: a refused record releases nothing"); }

    /* 5. another vault's record */
    { uint8_t other[32]; for (int i = 0; i < 32; i++) other[i] = (uint8_t)(0x11 * i);
      seal_master(other); uint8_t s2[600]; size_t s2n;
      run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), s2, &s2n);
      seal_master(spk);
      CHECK(run(VLT_OP_OPEN, s2, s2n, out, &on) == VLT_E_AUTH, "OPEN: a record sealed by another vault (other words) is refused"); }

    /* 6. input shape refused before any SE work */
    { int o = opens;
      uint8_t bad[600]; memcpy(bad, hdr, 13);
      bad[13] = 0; bad[14] = 'x';
      CHECK(run(VLT_OP_SEAL, bad, 15, NULL, NULL) == VLT_E_INPUT, "SEAL: site length 0 refused");
      bad[13] = 10; memcpy(bad + 14, "abc", 3);
      CHECK(run(VLT_OP_SEAL, bad, 17, NULL, NULL) == VLT_E_INPUT, "SEAL: site longer than the plaintext refused");
      CHECK(run(VLT_OP_SEAL, bad, 14, NULL, NULL) == VLT_E_INPUT, "SEAL: plaintext of 1 byte (no site) refused");
      memset(bad + 13, 'a', 500); bad[13] = 5;
      CHECK(run(VLT_OP_SEAL, bad, 13 + VLT_PT_MAX + 1, NULL, NULL) == VLT_E_INPUT, "SEAL: plaintext over 431 bytes refused");
      memset(bad + 13, 'a', 300); bad[13] = 254;
      CHECK(run(VLT_OP_SEAL, bad, 13 + 300, NULL, NULL) == VLT_E_INPUT, "SEAL: site length 254 refused (review: past the tag buffer)");
      bad[13] = 255;
      CHECK(run(VLT_OP_SEAL, bad, 13 + 300, NULL, NULL) == VLT_E_INPUT, "SEAL: site length 255 refused");
      { uint8_t t[32]; memset(t, 0xAA, 32); uint8_t big[300]; memset(big, 1, sizeof big); vlt_sub(g_kg0, "SITE", big, 254, t);
        uint8_t z = 0; for (int i = 0; i < 32; i++) z |= t[i];
        CHECK(z == 0, "vlt_sub refuses a site over 253 bytes (zero output, no overflow)"); }
      CHECK(run(VLT_OP_OPEN, sealed, sn - 1, NULL, NULL) == VLT_E_INPUT, "OPEN: a length that is not header + 16k + MAC refused");
      CHECK(run(VLT_OP_OPEN, sealed, VLT_OVER, NULL, NULL) == VLT_E_INPUT, "OPEN: no ciphertext block refused");
      CHECK(run(VLT_OP_TAG, sealed, 0, NULL, NULL) == VLT_E_INPUT && run(VLT_OP_TAG, bad, 254, NULL, NULL) == VLT_E_INPUT, "TAG: empty or over 253 bytes refused");
      CHECK(run(10, sealed, sn, NULL, NULL) == VLT_E_INPUT, "unknown op refused");
      put(VLT_OP_OPEN, sealed, sn); g_vlt_in[1] = 0x02; g_vlt_in[2] = 0x00; do_vault();
      CHECK(g_vlt_out[5] == VLT_E_INPUT, "length field over 511 refused");
      g_vlt_in_valid = 0; do_vault();
      CHECK(g_vlt_out[5] == VLT_E_INPUT, "no VAULT_IN: refused");
      CHECK(opens == o, "every refused shape: no SE session was opened"); }

    /* 7. keys, Door 1, master, session */
    g_keys_valid = 0; CHECK(run(VLT_OP_TAG, (const uint8_t *)"a", 1, NULL, NULL) == VLT_E_KEYS, "no keys: VLT_E_KEYS"); g_keys_valid = 1;
    g_door1_locked = 0; CHECK(run(VLT_OP_OPEN, sealed, sn, NULL, NULL) == VLT_E_KEYS, "no Door-1 boot lock this life: VLT_E_KEYS"); g_door1_locked = 1;
    master_ok = 0; give_pkm(); { uint8_t l = g_vlt_open_left;
      CHECK(run(VLT_OP_OPEN, sealed, sn, NULL, NULL) == VLT_E_MASTER && g_vlt_open_left == l, "master not readable (KEY locked): VLT_E_MASTER, no budget used"); }
    CHECK(sessions_live == 0, "master refused: the session is still closed"); master_ok = 1; give_pkm();
    fail_open = 1; CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), NULL, NULL) == VLT_E_OPEN, "session refused: VLT_E_OPEN"); fail_open = 0;

    /* 8. sizes and padding edges, random round trips */
    { int ok = 1; uint8_t s1[600], s2[600]; size_t n1, n2;
      for (size_t extra = 0; extra + 1 + 3 <= VLT_PT_MAX; extra += (extra < 40 ? 1 : 37)) {
        size_t p = mk_pt(pt, "a.b", extra, (uint8_t)extra);
        if (run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, p), s1, &n1)) { ok = 0; break; }
        g_vlt_open_left = 32; g_vlt_tag_left = 32;
        if (run(VLT_OP_OPEN, s1, n1, out, &on) || on != 13 + p || memcmp(out + 13, pt, p)) { ok = 0; break; }
      }
      size_t p = mk_pt(pt, "a.b", VLT_PT_MAX - 4, 1);
      CHECK(p == VLT_PT_MAX && run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, p), s1, &n1) == 0 && n1 <= VLT_DATA_MAX, "431-byte plaintext seals and fits VAULT_IN for a later OPEN");
      g_vlt_open_left = 32; g_vlt_tag_left = 32;
      CHECK(ok && run(VLT_OP_OPEN, s1, n1, out, &on) == 0 && !memcmp(out + 13, pt, p), "every plaintext length 4..431 (incl. whole-block padding) round-trips");
      run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), s1, &n1); run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), s2, &n2);
      CHECK(n1 == n2 && memcmp(s1 + 21, s2 + 21, 16) != 0 && memcmp(s1 + 37, s2 + 37, n1 - 69) != 0, "the same record sealed twice: fresh IV, different ciphertext"); }
    { int ok = 1;
      for (int t = 0; t < 2000 && ok; t++) {
        size_t sl = 1 + rand() % 60, ex = rand() % (VLT_PT_MAX - 1 - sl); char site[64];
        for (size_t i = 0; i < sl; i++) { site[i] = (char)('a' + rand() % 26); }
        site[sl] = 0;
        size_t p = mk_pt(pt, site, ex, (uint8_t)rand());
        for (size_t i = 0; i < 13; i++) hdr[i] = (uint8_t)rand();
        if (hdr[12] == VLT_KIND_TOTP) hdr[12] = 1;   /* v17: a kind 3 record never OPENs (tested in section 14) */
        uint8_t s1[600], t1[8]; size_t n1;
        if (run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, p), s1, &n1)) ok = 0;
        g_vlt_open_left = 32; g_vlt_tag_left = 32;
        if (ok && (run(VLT_OP_OPEN, s1, n1, out, &on) || on != 13 + p || memcmp(out, hdr, 13) || memcmp(out + 13, pt, p))) ok = 0;
        if (ok && (run(VLT_OP_TAG, (const uint8_t *)site, sl, t1, NULL) || memcmp(t1, s1 + 13, 8))) ok = 0;
      }
      CHECK(ok, "2000 random records: SEAL, OPEN and TAG agree"); }

    /* 9. the budget (P5 = C+, 2 Nov 2026) */
    { g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; g_vlt_refills = 0; int ok = 1;
      run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), sealed, &sn);
      for (int i = 0; i < VLT_PER_SITTING; i++) if (run(VLT_OP_OPEN, sealed, sn, NULL, NULL) != 0) ok = 0;
      int o = opens;
      CHECK(ok && run(VLT_OP_OPEN, sealed, sn, out, &on) == VLT_E_BUDGET && on == 0, "the 33rd OPEN of a sitting is refused (VLT_E_BUDGET), nothing released");
      CHECK(opens == o, "a spent budget opens no SE session");
      CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), NULL, NULL) == 0 && run(VLT_OP_TAG, (const uint8_t *)"x", 1, NULL, NULL) == 0, "SEAL and TAG still work with the OPEN budget spent");
      int ls = life_saves; memset(g_hash_in, 0, 32); memcpy(g_hash_in, "123456", 6); g_hash_in_valid = 1; do_uvset();
      CHECK(g_vlt_open_left == VLT_PER_SITTING && g_vlt_tag_left == VLT_PER_SITTING && g_vlt_refills == 1 && life_saves == ls + 1, "UVSET refills both budgets, counts one refill and saves the life token");
      CHECK(run(VLT_OP_OPEN, sealed, sn, out, &on) == 0, "an OPEN works again after the refill");
      memset(g_hash_in, 0, 32); memcpy(g_hash_in, "123456", 6); g_hash_in_valid = 1; g_vlt_open_left = 0; do_uvcheck();
      CHECK(g_vlt_open_left == VLT_PER_SITTING && g_vlt_refills == 2, "a right UVCHECK (the PIN re-ask) refills too");
      memset(g_hash_in, 0, 32); memcpy(g_hash_in, "999999", 6); g_hash_in_valid = 1; g_vlt_open_left = 0; do_uvcheck();
      CHECK(g_vlt_open_left == 0 && g_vlt_refills == 2, "a wrong UVCHECK does not refill");
      for (int i = 0; i < 5; i++) { memset(g_hash_in, 0, 32); memcpy(g_hash_in, "123456", 6); g_hash_in_valid = 1; g_vlt_open_left = 0; do_uvset(); }
      CHECK(g_vlt_refills == VLT_REFILLS_MAX && g_vlt_open_left == 0, "the 5th refill of a life is refused: 4 refills, 160 OPENs per life, then only a power cycle");
      g_vlt_tag_left = 1;
      CHECK(run(VLT_OP_TAG, (const uint8_t *)"a.example", 9, NULL, NULL) == 0 && g_vlt_tag_left == 0, "TAG uses its own budget");
      o = opens;
      CHECK(run(VLT_OP_TAG, (const uint8_t *)"b.example", 9, out, &on) == VLT_E_TAGBUDGET && on == 0 && opens == o, "the 33rd TAG of a sitting is refused (VLT_E_TAGBUDGET) before any SE session");
      CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), NULL, NULL) == VLT_E_TAGBUDGET, "SEAL draws on the TAG budget (review M2: its output carries a chosen site's tag)");
      g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; { uint8_t r0 = g_vlt_refills; memset(g_hash_in, 0, 32); memcpy(g_hash_in, "123456", 6); g_hash_in_valid = 1; do_uvset();
      CHECK(g_vlt_refills == r0, "a PIN entry with both budgets full counts no refill (review M3)"); }
      g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; g_vlt_refills = 0; }

    /* 10. the door picks the copy and the outer key (2b, Vault spec v0.25 1b) */
    /* 10. v19 (one door one PIN): only the passkey session's master, only in a PASSKEY life, only at V_3 */
    { g_door = DOOR_PASSKEY; int o = opens;
      CHECK(run(VLT_OP_OPEN, sealed, sn, out, &on) == 0 && opens > o, "v19: PASSKEY life, PKM_IN at V_3: the record opens");
      g_door = DOOR_NOSTR;
      CHECK(run(VLT_OP_OPEN, sealed, sn, out, &on) == VLT_E_MASTER, "v19: NOSTR life: refused (no NOSTR copy of the master any more)");
      g_door = DOOR_PASSKEY; fake_pcr[5] ^= 1;
      CHECK(run(VLT_OP_OPEN, sealed, sn, out, &on) == VLT_E_MASTER, "v19: latch not at V_3 (window burned): refused"); v3_value(fake_pcr);
      g_pkm_in[50] ^= 1;
      CHECK(run(VLT_OP_OPEN, sealed, sn, out, &on) == VLT_E_MASTER, "v19: a bad tag on PKM_IN: refused"); give_pkm();
      CHECK(master_obj_touched == 0, "v19: the G0 never asks for K_PK, PK_MASTER_P, K_PKN or PK_MASTER");
      CHECK(daily_used == 0, "the daily wrap key is never asked for by a VAULT op"); }

    /* 12. v15: the import window (Vault spec 7f, P4-4, 3 Nov 2026) */
    { uint8_t s1[600]; size_t n1; int o;
      #define PIN_OK()  do { memset(g_hash_in, 0, 32); memcpy(g_hash_in, "123456", 6); g_hash_in_valid = 1; } while (0)
      #define PIN_BAD() do { memset(g_hash_in, 0, 32); memcpy(g_hash_in, "999999", 6); g_hash_in_valid = 1; } while (0)
      g_door = DOOR_PASSKEY; g_vlt_refills = 0; PIN_OK(); do_uvset();       /* an unlock on the KEY: UV reference set */
      g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = 0;             /* the sitting's TAG budget spent */
      o = opens;
      CHECK(run(VLT_OP_IMPORT, NULL, 0, NULL, NULL) == VLT_E_IMPORT && opens == o, "IMPORT without a PIN check just before: refused (VLT_E_IMPORT), no SE session");
      PIN_BAD(); do_uvcheck();
      CHECK(run(VLT_OP_IMPORT, NULL, 0, NULL, NULL) == VLT_E_IMPORT, "a wrong PIN check does not arm IMPORT");
      PIN_OK(); do_uvcheck(); run(VLT_OP_TAG, (const uint8_t *)"x", 1, NULL, NULL);
      CHECK(run(VLT_OP_IMPORT, NULL, 0, NULL, NULL) == VLT_E_IMPORT, "the arm is spent by the very next VAULT op (a TAG in between)");
      g_door = DOOR_NOSTR; PIN_OK(); do_uvcheck();
      CHECK(run(VLT_OP_IMPORT, NULL, 0, NULL, NULL) == VLT_E_IMPORT && !g_imp_used, "v19: IMPORT in a NOSTR life: refused, nothing used (imports happen in VAULT mode)");
      g_door = DOOR_PASSKEY; master_ok = 0; give_pkm(); PIN_OK(); do_uvcheck();
      CHECK(run(VLT_OP_IMPORT, NULL, 0, NULL, NULL) == VLT_E_MASTER && !g_imp_used && !g_imp_on, "v19: no master from the passkey session: refused, the life's window not used");
      master_ok = 1; give_pkm(); PIN_OK(); do_uvcheck(); g_vlt_tag_left = 0;
      { int ls = life_saves;
      CHECK(run(VLT_OP_IMPORT, NULL, 0, out, &on) == 0 && on == 4 && out[0] == (VLT_IMP_MAX >> 8) && out[1] == (VLT_IMP_MAX & 0xFF) && out[2] == (VLT_IMP_MAX >> 8) && out[3] == (VLT_IMP_MAX & 0xFF) && g_imp_on && g_imp_used && life_saves > ls, "right PIN check, then IMPORT: window open, VLT_IMP_MAX (450 from v23) SEALs and TAGs, the life token saved (window used)"); }
      { int ok = 1; for (int i = 0; i < (int)VLT_IMP_MAX; i++) { if (run(VLT_OP_TAG, (const uint8_t *)"imp.example", 11, NULL, NULL)) ok = 0; if (run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), s1, &n1)) ok = 0; }
        CHECK(ok && g_vlt_tag_left == 0 && g_imp_seal == 0 && g_imp_tag == 0, "VLT_IMP_MAX SEALs and TAGs in the window with the sitting's TAG budget at 0 (the window pays for SEAL's tag)"); }
      CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), NULL, NULL) == VLT_E_TAGBUDGET && run(VLT_OP_TAG, (const uint8_t *)"y", 1, NULL, NULL) == VLT_E_TAGBUDGET, "the 301st: back on the sitting's budget (spent: refused)");
      g_vlt_open_left = 0;
      CHECK(run(VLT_OP_OPEN, s1, n1, NULL, NULL) == VLT_E_BUDGET, "the window never pays for an OPEN");
      PIN_OK(); do_uvcheck();
      CHECK(run(VLT_OP_IMPORT, NULL, 0, NULL, NULL) == VLT_E_IMPORT, "a second window in the same life: refused");
      /* a lock ends a window: a fresh life */
      g_imp_used = 0; PIN_OK(); do_uvcheck(); run(VLT_OP_IMPORT, NULL, 0, NULL, NULL); g_vlt_tag_left = 0;
      CHECK(g_imp_on && run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), NULL, NULL) == 0, "(new life) window open, a SEAL is paid by it");
      do_uvclear();
      CHECK(!g_imp_on && run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), NULL, NULL) == VLT_E_TAGBUDGET, "a lock (UVCLEAR) ends the window");
      g_imp_used = 0; PIN_OK(); do_uvset(); PIN_OK(); do_uvcheck(); run(VLT_OP_IMPORT, NULL, 0, NULL, NULL);
      PIN_OK(); do_uvset(); g_vlt_tag_left = 0;
      CHECK(!g_imp_on && g_imp_used && run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), NULL, NULL) == VLT_E_TAGBUDGET, "an unlock (UVSET) ends it too, and the life's window stays used");
      CHECK(run(10, NULL, 0, NULL, NULL) == VLT_E_INPUT && run(VLT_OP_IMPORT, (const uint8_t *)"x", 1, NULL, NULL) == VLT_E_INPUT, "IMPORT with data: refused");
      g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; g_vlt_refills = 0; g_imp_used = 0; imp_end(); }

    /* 14. v17: TOTP (Josh's ruling B, 7 Nov 2026): the secret never leaves the G0 */
    { uint8_t tp[300], s3[600], o3[600]; size_t tn = 0, n3, m3; uint8_t h3[13] = {7,7,7,7,7,7,7,7, 0,0,0,60, VLT_KIND_TOTP};
      const char *site = "github.com", *acct = "josh"; const char *sec = "12345678901234567890";   /* RFC 6238 SHA-1 key */
      tp[tn++] = (uint8_t)strlen(site); memcpy(tp + tn, site, strlen(site)); tn += strlen(site);
      tp[tn++] = (uint8_t)strlen(acct); memcpy(tp + tn, acct, strlen(acct)); tn += strlen(acct);
      tp[tn++] = 20; memcpy(tp + tn, sec, 20); tn += 20; tp[tn++] = 8; tp[tn++] = 30;
      g_door = DOOR_PASSKEY; g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; g_totp_last = 0; g_lbl_used = 0;
      CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, h3, tp, tn), s3, &n3) == 0, "a TOTP record (kind 3) seals");
      uint8_t req[620]; size_t rn;
      #define TOTP_REQ(T) do { uint64_t _t = (T); for (int i = 0; i < 8; i++) req[i] = (uint8_t)(_t >> (56 - 8 * i)); memcpy(req + 8, s3, n3); rn = 8 + n3; } while (0)
      { uint8_t ol = g_vlt_open_left; int o0 = opens; TOTP_REQ(59);
        CHECK(run(VLT_OP_TOTP, req, rn, o3, &m3) == 0 && m3 == 6 && o3[5] == 30, "TOTP at t=59: ok, 6 bytes out (code, digits, period 30)");
        uint32_t code = (uint32_t)o3[0] << 24 | (uint32_t)o3[1] << 16 | (uint32_t)o3[2] << 8 | o3[3];
        CHECK(code == 94287082u && o3[4] == 8, "the code is RFC 6238's 94287082 (SHA-1, 8 digits, t=59)");
        CHECK(g_vlt_open_left == ol - 1 && opens == o0 + 1 && sessions_live == 0, "one OPEN from the budget, one SE session, closed");
        int leak = 0; for (size_t i = 0; i + 20 <= sizeof(g_vlt_out); i++) if (!memcmp(g_vlt_out + i, sec, 20)) leak = 1;
        CHECK(!leak, "the secret appears nowhere in VAULT_OUT"); }
      { TOTP_REQ(1111111109ull); g_totp_last = 0;
        CHECK(run(VLT_OP_TOTP, req, rn, o3, &m3) == 0, "TOTP at t=1111111109: ok");
        uint32_t code = (uint32_t)o3[0] << 24 | (uint32_t)o3[1] << 16 | (uint32_t)o3[2] << 8 | o3[3];
        CHECK(code == 7081804u, "the code is RFC 6238's 07081804"); }
      { TOTP_REQ(1111111109ull - 61); uint8_t ol = g_vlt_open_left; int o0 = opens;
        CHECK(run(VLT_OP_TOTP, req, rn, NULL, NULL) == VLT_E_TIME && g_vlt_open_left == ol && opens == o0, "61 s back from the last code: refused before any SE session, nothing spent"); }
      { TOTP_REQ(1111111109ull + 1201);
        CHECK(run(VLT_OP_TOTP, req, rn, NULL, NULL) == VLT_E_TIME, "1201 s forward: refused"); }
      { TOTP_REQ(1111111109ull - 60);
        CHECK(run(VLT_OP_TOTP, req, rn, NULL, NULL) == 0, "60 s back: allowed"); }
      { TOTP_REQ(1111111109ull - 60 + 1200);
        CHECK(run(VLT_OP_TOTP, req, rn, NULL, NULL) == 0 && g_totp_last == 1111111109ull + 1140, "1200 s forward of the last: allowed, and it becomes the last"); }
      { uint8_t ol = g_vlt_open_left;
        CHECK(run(VLT_OP_OPEN, s3, n3, NULL, NULL) == VLT_E_INPUT && g_vlt_open_left == ol, "OPEN refuses a TOTP record: the secret never goes to the ESP32"); }
      { CHECK(run(VLT_OP_LABEL, s3, n3, o3, &m3) == 0 && m3 == 2 + 13 + 1 + strlen(site) + 1 + strlen(acct) && !memcmp(o3 + 15, tp, 1 + strlen(site) + 1 + strlen(acct)), "LABEL on a TOTP record: site and account only");
        int leak = 0; for (size_t i = 0; i + 20 <= sizeof(g_vlt_out); i++) if (!memcmp(g_vlt_out + i, sec, 20)) leak = 1;
        CHECK(!leak, "LABEL: the secret appears nowhere in VAULT_OUT"); }
      { uint8_t t[620]; g_totp_last = 0; TOTP_REQ(59); memcpy(t, req, rn); t[8 + 12] = VLT_KIND_PASSWORD;
        CHECK(run(VLT_OP_TOTP, t, rn, NULL, NULL) == VLT_E_INPUT, "TOTP on a record whose kind byte says 2: refused"); }
      { uint8_t t[620]; memcpy(t, s3, n3); t[12] = VLT_KIND_PASSWORD;
        CHECK(run(VLT_OP_OPEN, t, n3, NULL, NULL) == VLT_E_AUTH, "a TOTP record relabelled kind 2 for OPEN: the MAC fails"); }
      { uint8_t ps[600]; size_t pn2; TOTP_REQ(59);
        CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, (const uint8_t[13]){6,6,6,6,6,6,6,6,0,0,0,61,VLT_KIND_TOTP}, pt, ptn), ps, &pn2) == 0, "a kind 3 record of the wrong shape seals (SEAL checks only the site)");
        uint8_t r2[620]; for (int i = 0; i < 8; i++) r2[i] = req[i]; memcpy(r2 + 8, ps, pn2);
        CHECK(run(VLT_OP_TOTP, r2, 8 + pn2, NULL, NULL) == VLT_E_AUTH, "TOTP on it: refused (not a TOTP record's shape)"); }
      { g_vlt_open_left = 0; TOTP_REQ(59);
        CHECK(run(VLT_OP_TOTP, req, rn, NULL, NULL) == VLT_E_BUDGET, "budget spent: refused"); }
      CHECK(run(VLT_OP_TOTP, s3, 7, NULL, NULL) == VLT_E_INPUT, "too short: refused");
      #undef TOTP_REQ
      g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; g_totp_last = 0; g_lbl_used = 0; }

    /* 13. v15: LABEL (Vault spec 7f, P4-8, 3 Nov 2026) */
    { uint8_t pw[512], s2[600], o2[600]; size_t pn = 0, n2, n3; uint8_t h2[13] = {9,9,9,9,9,9,9,9, 0,0,0,50, VLT_KIND_PASSWORD};
      const char *site = "github.com", *user = "josh@favilla.io", *pwd = "correct horse battery", *note = "work";
      pw[pn++] = (uint8_t)strlen(site); memcpy(pw + pn, site, strlen(site)); pn += strlen(site);
      pw[pn++] = (uint8_t)strlen(user); memcpy(pw + pn, user, strlen(user)); pn += strlen(user);
      pw[pn++] = (uint8_t)strlen(pwd); memcpy(pw + pn, pwd, strlen(pwd)); pn += strlen(pwd);
      pw[pn++] = (uint8_t)strlen(note); memcpy(pw + pn, note, strlen(note)); pn += strlen(note);
      memset(pw + pn, 0x11, 12); pn += 12;
      g_door = DOOR_PASSKEY; g_lbl_used = 0; g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING;
      CHECK(run(VLT_OP_SEAL, in, mk_seal_in(in, h2, pw, pn), s2, &n2) == 0, "a password entry (kind 2) seals");
      int ls = life_saves; uint8_t ol = g_vlt_open_left;
      CHECK(run(VLT_OP_LABEL, s2, n2, o2, &n3) == 0, "LABEL ok");
      size_t k = 1 + strlen(site) + 1 + strlen(user);
      CHECK(n3 == 2 + 13 + k && o2[0] == ((VLT_LABEL_PER_LIFE - 1) >> 8) && o2[1] == ((VLT_LABEL_PER_LIFE - 1) & 0xFF) && !memcmp(o2 + 2, h2, 13) && !memcmp(o2 + 15, pw, k), "output: LABELs left (799 from v23) || hdr13 (id first) || site || username, exactly");
      { int leak = 0; for (size_t i = 0; i + strlen(pwd) <= sizeof(g_vlt_out); i++) if (!memcmp(g_vlt_out + i, pwd, strlen(pwd)) || !memcmp(g_vlt_out + i, "work", 4)) leak = 1;
        CHECK(!leak, "neither the password nor the note appears anywhere in VAULT_OUT"); }
      CHECK(g_vlt_open_left == ol && g_lbl_used == 1 && life_saves == ls + 1, "LABEL spends its own budget, never an OPEN, and saves the life token");
      CHECK(run(VLT_OP_OPEN, s2, n2, o2, &n3) == 0 && n3 == 13 + pn && g_vlt_open_left == ol - 1, "the same record still opens in full with OPEN (one OPEN)");
      { int o0 = opens; CHECK(run(VLT_OP_LABEL, sealed, sn, NULL, NULL) == VLT_E_INPUT && opens == o0, "a passkey record (kind 1): refused before any SE session"); }
      { uint8_t t[600]; memcpy(t, s2, n2); t[12] = 1;
        CHECK(run(VLT_OP_LABEL, t, n2, NULL, NULL) == VLT_E_INPUT, "kind byte changed to 1: refused"); }
      { uint8_t t[600]; memcpy(t, sealed, sn); t[12] = VLT_KIND_PASSWORD; uint16_t u = g_lbl_used;
        CHECK(run(VLT_OP_LABEL, t, sn, NULL, NULL) == VLT_E_AUTH && g_lbl_used == u, "a passkey record relabelled kind 2: the MAC fails, nothing spent"); }
      { uint8_t t[600]; memcpy(t, s2, n2); t[40] ^= 1; uint16_t u = g_lbl_used;
        CHECK(run(VLT_OP_LABEL, t, n2, NULL, NULL) == VLT_E_AUTH && g_lbl_used == u, "one bit changed: refused, costs nothing"); }
      { uint8_t bad[64]; size_t bn = 0; bad[bn++] = 3; memcpy(bad + bn, "a.b", 3); bn += 3; bad[bn++] = 200; memcpy(bad + bn, "xy", 2); bn += 2;   /* username length past the end */
        run(VLT_OP_SEAL, in, mk_seal_in(in, h2, bad, bn), s1x, &n2x);
        uint16_t u = g_lbl_used;
        CHECK(run(VLT_OP_LABEL, s1x, n2x, NULL, NULL) == VLT_E_AUTH && g_lbl_used == u, "a sealed kind-2 record with a username running past the end: refused, nothing out, nothing spent"); }
      g_vlt_open_left = 0;
      CHECK(run(VLT_OP_LABEL, s2, n2, NULL, NULL) == 0, "LABEL works with the OPEN budget spent");
      g_lbl_used = VLT_LABEL_PER_LIFE - 1;
      CHECK(run(VLT_OP_LABEL, s2, n2, o2, &n3) == 0 && o2[0] == 0 && o2[1] == 0, "the 400th: ok, 0 left");
      CHECK(run(VLT_OP_LABEL, s2, n2, NULL, NULL) == VLT_E_LABEL && g_lbl_used == VLT_LABEL_PER_LIFE, "the 801st: refused (VLT_E_LABEL)");
      PIN_OK(); do_uvset(); PIN_OK(); do_uvcheck();
      CHECK(run(VLT_OP_LABEL, s2, n2, NULL, NULL) == VLT_E_LABEL, "a PIN does not refill LABELs (only a power cycle)");
      g_lbl_used = 0; g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; imp_end(); g_imp_used = 0; }

#ifdef HOST_VPUB
    /* 11. v14: the vault backup publishing key (vpub_glue.inc) with real libsecp256k1 */
    { g_ctx = secp256k1_context_preallocated_create(g_ctx_buf, SECP256K1_CONTEXT_NONE);
      uint8_t o72[80], ref_k[32], ref_p[32], ref_c[8], h[32];
      /* independent reference: K_vault -> k = first HMAC(kv, "PUB" || ctr) that is a valid key */
      for (int c = 0; c < 256; c++) { uint8_t m[4] = {'P','U','B',(uint8_t)c}; ref_hmac(kv, 32, m, 4, ref_k); if (secp256k1_ec_seckey_verify(g_ctx, ref_k)) break; }
      { secp256k1_keypair kp; secp256k1_xonly_pubkey xp; secp256k1_keypair_create(g_ctx, &kp, ref_k); secp256k1_keypair_xonly_pub(g_ctx, &xp, NULL, &kp); secp256k1_xonly_pubkey_serialize(g_ctx, ref_p, &xp); }
      ref_hmac(kv, 32, (const uint8_t *)"CHK", 3, h); memcpy(ref_c, h, 8);
      g_door = DOOR_PASSKEY; uint8_t ol = g_vlt_open_left, tl = g_vlt_tag_left;
      CHECK(run(VLT_OP_PUBSEAL, NULL, 0, o72, &on) == 0 && on == 72, "PUBSEAL in a PASSKEY life: 72 bytes");
      CHECK(!memcmp(o72 + 32, ref_p, 32) && !memcmp(o72 + 64, ref_c, 8), "PUBSEAL: x-only P and the check value match an independent derivation");
      CHECK(memcmp(o72, ref_k, 32) != 0, "PUBSEAL: the key leaves only sealed under K_G0");
      { uint8_t iv[16], k2[32]; vpub_iv(iv); mbedtls_aes_context a; mbedtls_aes_init(&a); mbedtls_aes_setkey_dec(&a, g_kg0, 256);
        mbedtls_aes_crypt_cbc(&a, MBEDTLS_AES_DECRYPT, 32, iv, o72, k2); mbedtls_aes_free(&a);
        CHECK(!memcmp(k2, ref_k, 32), "PUBSEAL: sealed = AES-CBC(K_G0, vault-pub IV, k_pub)"); }
      CHECK(g_vlt_open_left == ol && g_vlt_tag_left == tl, "PUBSEAL spends no OPEN and no TAG");
      CHECK(run(VLT_OP_PUBSEAL, (const uint8_t *)"x", 1, o72, &on) == VLT_E_INPUT, "PUBSEAL with data: refused");
      uint8_t p2[80]; CHECK(run(VLT_OP_PUBSEAL, NULL, 0, p2, &on) == 0 && !memcmp(p2 + 32, o72 + 32, 40), "PUBSEAL is deterministic (same P and check)");
      /* VSIGN_INIT: NOSTR life, the copy on the SE (IV16 || the sealed bytes; v19: the daily layer is the identity here) */
      memset(vpub_blob, 0, 16); memcpy(vpub_blob + 16, o72, 32); vpub_ok = 1; g_door = DOOR_NOSTR;
      uint8_t msg[32], t[32], hc[32]; for (int i = 0; i < 32; i++) { msg[i] = (uint8_t)(0x11 * i); t[i] = (uint8_t)(0x77 + i); }
      ae_host_commit(AE_KIND_SCHNORR, t, hc);
      memcpy(g_ae_in, msg, 32); memcpy(g_ae_in + 32, hc, 32); g_ae_in_valid = 1; ae_wipe();
      int o0 = opens;
      CHECK(do_vsign_init() == 0 && g_ae.kind == AE_KIND_SCHNORR && g_ae.vault == 1 && !memcmp(g_ae.pub33, ref_p, 32), "VSIGN_INIT: pending Schnorr with k_pub, P kept for the release check");
      CHECK(opens == o0 + 1 && sessions_live == 0, "VSIGN_INIT: one SE session, closed");
      CHECK(daily_used > 0 && master_obj_touched == 0, "v19: VSIGN_INIT strips the daily layer, never K_PKN or K_PK");
      CHECK(!memcmp(g_ae.key, ref_k, 32) && !memcmp(g_sig_out, g_ae.r0, 33), "VSIGN_INIT: the key is k_pub and SIG_OUT carries R0");
      { uint8_t sig[64]; secp256k1_xonly_pubkey xp; secp256k1_xonly_pubkey_parse(g_ctx, &xp, ref_p);
        int ok = ae_schnorr_finish(g_ctx, g_ae.key, g_ae.msg, g_ae.k0, g_ae.r0, t, sig) == 0 && secp256k1_schnorrsig_verify(g_ctx, sig, msg, 32, &xp);
        CHECK(ok, "the finished signature verifies against P (BIP-340)"); }
      CHECK(do_vsign_init() != 0 && g_ae.vault == 1, "a second VSIGN_INIT while one is pending: refused, the pending one kept");
      ae_wipe(); g_door1_locked = 0;
      CHECK(do_vsign_init() != 0 && g_ae.kind == AE_KIND_NONE, "no Door-1 boot lock this life: refused");
      g_door1_locked = 1; vpub_ok = 0;
      CHECK(do_vsign_init() != 0 && g_ae.kind == AE_KIND_NONE && sessions_live == 0, "no VPUB copy on the SE: refused, session closed");
      vpub_ok = 1; vpub_blob[20] ^= 1;
      { int r = do_vsign_init(); CHECK(r != 0 || memcmp(g_ae.pub33, ref_p, 32) != 0, "an altered copy never signs as P"); ae_wipe(); }
      /* vector for the ESP32's own derivation (vault_backup.cpp host test) */
      { printf("VECTOR spk="); for (int i = 0; i < 32; i++) printf("%02x", spk[i]);
        printf(" P="); for (int i = 0; i < 32; i++) printf("%02x", ref_p[i]);
        printf(" chk="); for (int i = 0; i < 8; i++) printf("%02x", ref_c[i]); printf("\n"); }
    }
#endif
    /* 16. v24 (25 Nov 2026): the owner's vault limit, LIMIT (8) and SETLIM (9) */
    {   g_door = DOOR_PASSKEY; master_ok = 1; give_pkm(); imp_end(); g_imp_used = 0; g_vlt_refills = 0;
        g_vlt_limit = g_vlt_limit_next = 0; g_vlt_open_left = g_vlt_tag_left = 0;
        #define PIN_OK2() do { memset(g_hash_in, 0, 32); memcpy(g_hash_in, "123456", 6); g_hash_in_valid = 1; } while (0)
        PIN_OK2(); do_uvset();
        uint8_t s4[600], o4[600]; size_t n4, m4; int o0 = opens;
        CHECK(run(VLT_OP_LIMIT, NULL, 0, o4, &m4) == 0 && m4 == 6 && o4[0] == 0 && o4[1] == 0 && o4[2] == 0xFF && o4[3] == 0xFF && o4[5] == VLT_REFILLS_MAX && opens == o0,
              "LIMIT: no limit reads 0 / 0 / 0xFF / 0xFF, no SE session");
        CHECK(run(VLT_OP_LIMIT, (const uint8_t *)"x", 1, NULL, NULL) == VLT_E_INPUT, "LIMIT with data: refused");
        { int ok = 1; for (int i = 0; i < 200; i++) { if (run(VLT_OP_SEAL, in, mk_seal_in(in, hdr, pt, ptn), s4, &n4)) ok = 0; if (run(VLT_OP_OPEN, s4, n4, NULL, NULL)) ok = 0; if (run(VLT_OP_TAG, (const uint8_t *)"z.example", 9, NULL, NULL)) ok = 0; }
          CHECK(ok && g_vlt_out[7] == 0xFF && g_vlt_open_left == 0 && g_vlt_tag_left == 0 && g_vlt_refills == 0, "no limit: 200 SEALs, OPENs and TAGs all served, nothing counted, byte 7 = 0xFF"); }
        { uint8_t L = 16; o0 = opens;
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == VLT_E_LIMIT && opens == o0 && host_lim_writes == 0, "SETLIM without a PIN check just before: refused (0xED), no SE session, nothing written");
          PIN_OK2(); do_uvcheck(); run(VLT_OP_LIMIT, NULL, 0, NULL, NULL);
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == VLT_E_LIMIT, "the arm is spent by any VAULT op in between (even LIMIT)");
          L = 20; PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == VLT_E_LIMIT && host_lim_writes == 0, "SETLIM 20 (not 0/8/16/32/64/128): refused");
          L = 16; g_door = DOOR_NOSTR; PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == VLT_E_LIMIT && host_lim_writes == 0, "SETLIM in a NOSTR life: refused");
          g_door = DOOR_PASSKEY; master_ok = 0; give_pkm(); PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == VLT_E_MASTER && host_lim_writes == 0, "SETLIM without the passkey session's master: refused, nothing written");
          master_ok = 1; give_pkm(); host_lim_fail = 1; PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == VLT_E_LIMIT && g_vlt_limit == 0 && g_vlt_limit_next == 0, "the flash write fails: refused, nothing changes in RAM");
          host_lim_fail = 0; PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, o4, &m4) == 0 && m4 == 6 && host_lim_stored == 16 && g_vlt_limit == 16 && g_vlt_limit_next == 16 && o4[0] == 16 && o4[2] == 16 && o4[3] == 16 && g_vlt_out[7] == 16,
                "SETLIM 16 from none: stored, applies at once, both budgets start full at 16"); }
        { int ok = 1; for (int i = 0; i < 16; i++) if (run(VLT_OP_OPEN, s4, n4, NULL, NULL)) ok = 0;
          CHECK(ok && run(VLT_OP_OPEN, s4, n4, NULL, NULL) == VLT_E_BUDGET, "with 16: the 17th OPEN of the sitting is refused"); }
        { uint8_t L = 8; g_vlt_open_left = 12; g_vlt_tag_left = 3; PIN_OK2(); do_uvcheck();
          /* the right UVCHECK refilled to 16 first, then the stricter 8 caps it */
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == 0 && g_vlt_limit == 8 && g_vlt_open_left == 8 && g_vlt_tag_left == 8 && host_lim_stored == 8, "stricter (16 -> 8): at once, the budgets capped at 8"); }
        { uint8_t L = 128; PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, o4, &m4) == 0 && g_vlt_limit == 8 && g_vlt_limit_next == 128 && host_lim_stored == 128 && o4[0] == 8 && o4[1] == 128, "looser (8 -> 128): stored, but this life keeps 8");
          L = 0; PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == 0 && g_vlt_limit == 8 && g_vlt_limit_next == 0 && host_lim_stored == 0, "none (8 -> no limit): stored, this life keeps 8");
          g_vlt_open_left = 0; CHECK(run(VLT_OP_OPEN, s4, n4, NULL, NULL) == VLT_E_BUDGET, "a looser setting never lifts the limit of the life it was set in"); }
        { uint8_t L = 32; PIN_OK2(); do_uvcheck();
          CHECK(run(VLT_OP_SETLIM, &L, 1, NULL, NULL) == 0 && g_vlt_limit == 8 && g_vlt_limit_next == 32, "8 -> 32: next life");
          PIN_OK2(); do_uvset();
          CHECK(g_vlt_open_left == 8 && g_vlt_tag_left == 8, "a refill fills to the limit of this life (8), not the stored one"); }
        g_vlt_limit = g_vlt_limit_next = VLT_PER_SITTING; g_vlt_open_left = g_vlt_tag_left = VLT_PER_SITTING; g_vlt_refills = 0; }
    CHECK(master_obj_touched == 0, "v19: over the whole run the G0 never touched K_PK, PK_MASTER_P, K_PKN or PK_MASTER");
    CHECK(sessions_live == 0, "no SE session left open after the whole run");
    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
