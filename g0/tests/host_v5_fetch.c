/* Host test of the v5 G0 seed fetch: the real fetch_blob_se / g0_read_mode_pcr /
 * seed_inner_crypt source, extracted from main.c, run against a fake SE that
 * holds MODE_PCR and applies READ / WRITE(extend) exactly as the applet does. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "aes.h"
#include "scp03.h"
#include "se_objects.h"
#define KSE_LEN 16
#define KG0_LEN 32
#define KMODE_LEN 32
#define SEED_IN_LEN 96
#define BTC_OUT_LEN 192
#define STORE_IN_LEN 97
#define SS_OUTER_LEN 96u
#define SS_KIND_SEED 0u
#define SS_KIND_ENTROPY 1u
static uint8_t g_kse[KSE_LEN], g_kg0[KG0_LEN], g_kmode[KMODE_LEN];
static int g_keys_valid = 1;
uint32_t g_gen_off = 0x300;   /* v5.1: run the tests on generation 3 */
static uint8_t g_sig_out[64], g_btc_out[BTC_OUT_LEN];
static uint8_t g_seed_in[SEED_IN_LEN]; static int g_seed_in_valid = 0;
static uint8_t g_store_in[STORE_IN_LEN]; static int g_store_in_valid = 0;
static uint8_t g_pend_ihash[32], g_pend_kind = 0, g_pend_valid = 0;
static uint8_t g_door1_locked = 0;
static uint8_t g_seal_window = 0;
/* ── fake flash seed page (write-once, as key_store.c) ── */
static int ss_ok = 0; static uint8_t ss_kind, ss_outer[96], ss_ih[32]; static int ss_fail_write = 0;
static int ss_present(void) { return ss_ok; }
static int ss_load(uint8_t *k, uint8_t o[96], uint8_t ih[32]) { if (!ss_ok) return 0; if (k) *k = ss_kind; if (o) memcpy(o, ss_outer, 96); if (ih) memcpy(ih, ss_ih, 32); return 1; }
static int ss_store(uint8_t k, const uint8_t o[96], const uint8_t ih[32]) { if (ss_ok || ss_fail_write) return 0; ss_kind = k; memcpy(ss_outer, o, 96); memcpy(ss_ih, ih, 32); ss_ok = 1; return 1; }
static void secure_wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }
static void host_challenge(uint8_t hc[8]) { memset(hc, 0x11, 8); }
static void entropy_mix(const uint8_t *p, size_t n) { (void)p; (void)n; }
static int relay_xfer(void *c, const uint8_t *a, size_t al, uint8_t *r, size_t rc, size_t *rl) { (void)c;(void)a;(void)al;(void)r;(void)rc;(void)rl; return -1; }
/* ── fake SE ── */
static uint8_t SE_PCR[32]; static int se_open_ok = 1, n_extends = 0;
static uint8_t SE_D1[32]; static int se_d1_exists = 1, se_d1_g0_write = 1, n_d1_extends = 0;
int scp03_open(scp03_session_t *s, scp03_xfer_fn x, void *xc, const uint8_t kse[16], uint32_t auth, const uint8_t h[8], uint8_t cc[8]) {
    (void)x;(void)xc;(void)kse;(void)h; memset(s, 0, sizeof(*s)); if (cc) memset(cc, 0x22, 8);
    if (auth != SE_AUTH_OBJ_G0 || !se_open_ok) { s->stage = 2; return -1; } s->stage = 4; s->authed = 1; return 0; }
int scp03_cmd(scp03_session_t *s, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *d, size_t dl, int hasle, uint8_t *o, size_t oc, size_t *ol) {
    (void)hasle;(void)oc; s->nxfer++;
    if (ins == 0x02 && p1 == 0x00) {             /* READ MODE_PCR -> TLV 41 20 <32> */
        o[0] = 0x41; o[1] = 0x20; memcpy(o + 2, SE_PCR, 32); *ol = 34; s->last_sw = 0x9000; return 0; }
    uint32_t oid = dl >= 6 ? ((uint32_t)d[2] << 24 | (uint32_t)d[3] << 16 | (uint32_t)d[4] << 8 | d[5]) : 0;
    if (ins == 0x01 && p1 == 0x09 && dl == 40 && d[6] == 0x43 && oid == SE_OBJ_PCR_UNLOCK) {   /* Door-1 extend */
        if (!se_d1_exists) { s->last_sw = 0x6A82; return -1; }
        if (!se_d1_g0_write) { s->last_sw = 0x6986; return -1; }
        uint8_t b[64]; memcpy(b, SE_D1, 32); memcpy(b + 32, d + 8, 32); sha256(b, 64, SE_D1); n_d1_extends++; s->last_sw = 0x9000; return 0; }
    if (ins == 0x04 && p2 == 0x27 && oid == SE_OBJ_PCR_UNLOCK) {   /* CheckObjectExists, authenticated */
        o[0] = 0x41; o[1] = 0x01; o[2] = se_d1_exists ? 0x01 : 0x02; *ol = 3; s->last_sw = 0x9000; return 0; }
    if (ins == 0x01 && p1 == 0x09 && dl == 40 && d[6] == 0x43) {   /* WritePCR extend */
        uint8_t b[64]; memcpy(b, SE_PCR, 32); memcpy(b + 32, d + 8, 32); sha256(b, 64, SE_PCR); n_extends++; s->last_sw = 0x9000; return 0; }
    s->last_sw = 0x6985; return -1; }
int scp03_close(scp03_session_t *s) { memset(s, 0, sizeof(*s)); return 0; }
void scp03_wipe(scp03_session_t *s) { memset(s, 0, sizeof(*s)); }
#include "extracted.inc"
/* ── tests ── */
static uint8_t neutral[32], btc[32], spent[32];
static void set_latch(const uint8_t v[32]) { memcpy(SE_PCR, v, 32); }
static int fails = 0;
#define CHECK(c, m) do { if (c) printf("PASS  %s\n", m); else { printf("FAIL  %s\n", m); fails++; } } while (0)
int main(void) {
    for (int i = 0; i < 32; i++) { g_kg0[i] = (uint8_t)(0xA0 + i); g_kmode[i] = (uint8_t)(0x30 + i); }
    uint8_t z[32] = {0}, b[64]; sha256(z, 32, neutral);
    memcpy(b, neutral, 32); memcpy(b + 32, g_kmode, 32); sha256(b, 64, btc);
    memcpy(b, btc, 32); memcpy(b + 32, MODE_CONST_SPENT, 32); sha256(b, 64, spent);
    uint8_t seed[64], inner[64], pkt[96], out[64]; int step; uint8_t d[8];
    for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 7 + 3);
    memcpy(inner, seed, 64); seed_inner_crypt(inner, 1);           /* what SEEDSEAL stored, i.e. what the spend session yields */
    memset(pkt, 0, 96); memcpy(pkt, inner, 64); memcpy(pkt + 64, "FVI5", 4);   /* g0_pack_inner_packet */

    /* ── v5.1 onboarding: SEEDSEAL -> SEEDSTORE on this chip ── */
    uint8_t outer[96]; for (int i = 0; i < 96; i++) outer[i] = (uint8_t)(0xC0 ^ i);   /* stands in for the SE-wrapped blob */
    g_store_in[0] = 0; memcpy(g_store_in + 1, outer, 96); g_store_in_valid = 1;
    g_seal_window = 1; do_seedstore(); g_seal_window = 0;
    CHECK(g_sig_out[5] == 0xE8 && !ss_ok, "v5.1 SEEDSTORE with no SEEDSEAL this life -> refused 0xE8");
    memcpy(g_seed_in, seed, 64); g_seed_in_valid = 1;
    CHECK(do_seedseal() != 0, "v5.1 SEEDSEAL outside the onboarding seal window -> refused");
    g_store_in_valid = 1; do_seedstore();
    CHECK(g_sig_out[5] == 0xEB && !ss_ok, "v5.1 SEEDSTORE outside the seal window -> refused 0xEB");
    g_seal_window = 1;   /* SETKEYS ran this life */
    memcpy(g_seed_in, seed, 64); g_seed_in_valid = 1;
    CHECK(do_seedseal() == 0 && !memcmp(g_sig_out, inner, 64), "v5.1 SEEDSEAL -> the inner layer");
    g_store_in[0] = 1; g_store_in_valid = 1; do_seedstore();
    CHECK(g_sig_out[5] == 0xE9 && !ss_ok, "v5.1 SEEDSTORE with the wrong kind -> refused 0xE9");
    ss_fail_write = 1; g_store_in[0] = 0; g_store_in_valid = 1; do_seedstore();
    CHECK(g_sig_out[5] == 0xEA && !ss_ok, "v5.1 flash write failure -> 0xEA, nothing stored");
    ss_fail_write = 0; g_store_in_valid = 1; do_seedstore();
    { uint8_t h[32]; sha256(inner, 64, h);
      CHECK(g_sig_out[5] == 0 && ss_ok && ss_kind == 0 && !memcmp(ss_outer, outer, 96) && !memcmp(ss_ih, h, 32) && !memcmp(g_sig_out + 6, h, 32),
            "v5.1 SEEDSTORE -> outer blob + kind + inner hash on the G0"); }
    CHECK(g_seal_window == 0, "v5.1 a successful SEEDSTORE closes the seal window");
    g_seal_window = 1;   /* even with the window forced open, write-once holds */
    g_seed_in_valid = 1; CHECK(do_seedseal() != 0, "v5.1 SEEDSEAL once a seed is stored -> refused (no substitute seed)");
    g_store_in_valid = 1; do_seedstore(); CHECK(g_sig_out[5] == 0xE7, "v5.1 second SEEDSTORE -> refused 0xE7 (write-once)");
    do_seedget();
    CHECK(!memcmp(g_btc_out, "SGET", 4) && g_btc_out[5] == 0 && g_btc_out[6] == 0 && !memcmp(g_btc_out + 8, outer, 96), "v5.1 SEEDGET -> the stored outer blob");

    set_latch(btc); n_extends = 0;
    int rc = fetch_blob_se(pkt, 0, out, &step, d);
    CHECK(rc == 0 && step == 0 && !memcmp(out, seed, 64), "latch BTC + v5 packet -> the right seed");
    CHECK(!memcmp(SE_PCR, spent, 32) && n_extends == 1, "latch burned to SPENT before the seed is released");

    rc = fetch_blob_se(pkt, 0, out, &step, d);
    CHECK(rc != 0 && step == 9, "replaying the same packet after the burn -> refused (latch not BTC)");
    { int allz = 1; for (int i = 0; i < 64; i++) if (out[i]) allz = 0; CHECK(allz, "refused fetch leaves no seed bytes in the output"); }

    set_latch(neutral); rc = fetch_blob_se(pkt, 0, out, &step, d);
    CHECK(rc != 0 && step == 9, "latch NEUTRAL -> refused");
    uint8_t nostr[32]; memset(nostr, 0x55, 32); set_latch(nostr); rc = fetch_blob_se(pkt, 0, out, &step, d);
    CHECK(rc != 0 && step == 9, "latch NOSTR/other -> refused");

    uint8_t v3blob[96]; for (int i = 0; i < 96; i++) v3blob[i] = (uint8_t)(i * 13 + 1);   /* a v3 ESP32's raw SE blob */
    set_latch(btc); n_extends = 0; rc = fetch_blob_se(v3blob, 0, out, &step, d);
    CHECK(rc != 0 && step == 0xE6 && n_extends == 0 && !memcmp(SE_PCR, btc, 32), "v3 raw blob -> refused 0xE6, latch untouched");

    uint8_t s_save[32]; memcpy(s_save, g_kmode, 32); memset(g_kmode, 0, 32);
    rc = fetch_blob_se(pkt, 0, out, &step, d); CHECK(rc != 0 && step == 0xEF, "no S on this G0 -> refused 0xEF");
    memcpy(g_kmode, s_save, 32);

    set_latch(btc); se_open_ok = 0; rc = fetch_blob_se(pkt, 0, out, &step, d);
    CHECK(rc != 0 && step >= 1 && step <= 4 && !memcmp(SE_PCR, btc, 32), "SE session refused -> no seed, latch untouched");
    se_open_ok = 1;

    /* ── v5.1 binding: the packet must be the stored seed's inner layer ── */
    { uint8_t other[96]; memcpy(other, pkt, 96); other[5] ^= 1;
      set_latch(btc); n_extends = 0; rc = fetch_blob_se(other, 0, out, &step, d);
      CHECK(rc != 0 && step == 0xEA && n_extends == 0 && !memcmp(SE_PCR, btc, 32), "v5.1 a different inner packet -> refused 0xEA, latch not burned"); }
    set_latch(btc); n_extends = 0; rc = fetch_blob_se(pkt, 1, out, &step, d);
    CHECK(rc != 0 && step == 0xE9 && n_extends == 0, "v5.1 seed packet presented as an entropy wallet -> refused 0xE9");
    ss_ok = 0; set_latch(btc); rc = fetch_blob_se(pkt, 0, out, &step, d);
    CHECK(rc != 0 && step == 0xE8 && n_extends == 0, "v5.1 no seed stored on the G0 -> refused 0xE8");
    ss_ok = 1;

    /* ── v5.1 Door-1 boot lock ── */
    uint8_t d1_unlocked[32]; memset(d1_unlocked, 0x77, 32); memcpy(SE_D1, d1_unlocked, 32);
    g_door1_locked = 0; do_door1lock();
    CHECK(g_sig_out[5] == 0 && g_door1_locked && memcmp(SE_D1, d1_unlocked, 32) != 0 && n_d1_extends == 1, "v5.1 DOOR1LOCK extends the PCR off the unlocked value");
    se_d1_exists = 0; g_door1_locked = 0; do_door1lock();
    CHECK(g_sig_out[5] == 1 && g_door1_locked, "v5.1 DOOR1LOCK with the PCR absent (authenticated) -> locked");
    se_d1_exists = 1; se_d1_g0_write = 0; g_door1_locked = 0; do_door1lock();
    CHECK(g_sig_out[5] == 6 && !g_door1_locked, "v5.1 DOOR1LOCK refused by the SE (old PCR policy) -> NOT locked, Nostr stays off");
    se_d1_g0_write = 1; se_open_ok = 0; g_door1_locked = 0; do_door1lock();
    CHECK(g_sig_out[5] >= 1 && g_sig_out[5] <= 4 && !g_door1_locked, "v5.1 DOOR1LOCK with no SE session -> NOT locked");
    se_open_ok = 1;
    g_keys_valid = 0; g_door1_locked = 0; do_door1lock();
    CHECK(g_sig_out[5] == 0xE0 && !g_door1_locked, "v5.1 DOOR1LOCK with no keys -> 0xE0");
    g_keys_valid = 1;

    printf(fails ? "\n%d FAILED\n" : "\nall v5 / v5.1 G0 checks passed\n", fails);
    return fails != 0;
}
