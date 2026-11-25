/* host_ember_e2e.c — Emberwill end to end on the host. 28 Oct 2026.
 *
 * The real command core (src/ember.c over every ember module, btc.c,
 * antiexfil.c and libsecp256k1) driven by a stand-in ESP32 on a simulated
 * chain (easy test target, no retarget; the mainnet rules are proven in
 * host_ember_hdr):
 *   1. ceremony: EMBER_SET, then every signature as INIT -> R0, FINISH(t) -> r,
 *      each checked by the host relation x(R0 + H(R0||t)G) == r; blobs stored
 *   2. reboot right after the commit and every 2,500 blocks (flash restore)
 *   3. owner alive (PIN every 500 blocks, one Pulse, notes): the walk releases
 *      each refresh in its window, the "miner" includes it, proofs advance it
 *   4. owner silent: Afterglow, Kindling of the live coupon, proof, 6 deep,
 *      plan erased
 *   5. refusals along the way: release out of turn, wrong blob, tampered
 *      blob, bad proof, tier-3 before the owner key is bound
 * Every transaction the G0 releases is written to /tmp/ember_released.txt;
 * tools/check_released.py re-verifies them with embit (signatures, chain
 * links, locktime against the height they were mined at). */
#define EMBER_HOST_DEBUG 1
#include "ember.h"
#include "btc.h"
#include "antiexfil.h"
#include "sha256.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)
static secp256k1_context *ctx;
static void wr32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

/* ── G0 environment ─────────────────────────────────────────────────────── */
static uint8_t FL[3][ES_PAGE_SIZE];
static uint8_t *pg(uint32_t a) { return a >= ES_PLAN_ADDR ? FL[2] + (a - ES_PLAN_ADDR) : a >= ES_STATE_A_ADDR ? FL[0] + (a - ES_STATE_A_ADDR) : FL[1] + (a - ES_STATE_B_ADDR); }
static int erases;
static int f_erase(void *c, uint32_t a) { (void)c; memset(pg(a), 0xFF, ES_PAGE_SIZE); erases++; return 0; }
static int f_prog(void *c, uint32_t a, const uint8_t *d, size_t n) { (void)c; uint8_t *p = pg(a); for (size_t i = 0; i < n; i++) { if (p[i] != 0xFF) return -1; p[i] = d[i]; } return 0; }
static const uint8_t *f_map(void *c, uint32_t a) { (void)c; return pg(a); }
static uint32_t g_ms;
static uint32_t env_ms(void *u) { (void)u; return g_ms; }
static uint32_t g_rc;
static void env_rand(void *u, uint8_t o[32]) { (void)u; uint8_t s[8]; wr32(s, ++g_rc); wr32(s + 4, 0xE3B0); sha256(s, 8, o); }
static btc_xprv ACCT;
static int env_leaf(void *u, uint32_t ch, uint32_t ix, uint8_t key[32], uint8_t pub[33]) { (void)u; return btc_leaf(ctx, &ACCT, ch, ix, key, pub); }
static em_env_t ENV;

/* ── simulated chain + mempool ──────────────────────────────────────────── */
static const eh_params_t TPE = {
    .pow_limit = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu },
    .interval = 2016, .timespan = 1209600, .no_retarget = 1, .v2_height = 0, .v3_height = 0, .v4_height = 0,
};
#define BASE 900000u
#define MAXH 40000
static uint8_t HDR[MAXH][80]; static uint32_t NH;          /* HDR[i] is height BASE + i */
#define MAXTX 4
static uint8_t BTX[MAXH][MAXTX][32]; static uint8_t BNT[MAXH];   /* txids per block (0 = coinbase) */
static uint8_t MEM[8][1100]; static size_t MEML[8]; static int NMEM;
static void dsha(const uint8_t *d, size_t n, uint8_t o[32]) { uint8_t t[32]; sha256(d, n, t); sha256(t, 32, o); }
/* txid of a segwit transaction from its raw bytes (the stand-in ESP32 can parse) */
static void raw_txid(const uint8_t *r, size_t n, uint8_t id[32]) {
    static uint8_t s[1100]; size_t k = 0, p = 6; (void)n;
    memcpy(s, r, 4); k = 4;
    uint8_t nin = r[p]; size_t a = p; p++; p += nin * 41u;
    uint8_t nout = r[p]; p++; for (int i = 0; i < nout; i++) { p += 8; p += 1 + r[p]; }
    memcpy(s + k, r + a, p - a); k += p - a;
    for (int i = 0; i < nin; i++) { uint8_t items = r[p++]; for (int j = 0; j < items; j++) p += 1 + r[p]; }
    memcpy(s + k, r + p, 4); k += 4;
    dsha(s, k, id);
}
static void merkle_levels(uint8_t (*ids)[32], int n, uint8_t root[32]) {
    uint8_t lv[MAXTX + 1][32]; memcpy(lv, ids, 32 * n);
    while (n > 1) { if (n & 1) { memcpy(lv[n], lv[n - 1], 32); n++; } for (int i = 0; i < n / 2; i++) { uint8_t b[64]; memcpy(b, lv[2 * i], 32); memcpy(b + 32, lv[2 * i + 1], 32); dsha(b, 64, lv[i]); } n /= 2; }
    memcpy(root, lv[0], 32);
}
static int merkle_branch(uint8_t (*ids)[32], int n, int idx, uint8_t br[][32]) {
    uint8_t lv[MAXTX + 1][32]; memcpy(lv, ids, 32 * n); int d = 0;
    while (n > 1) { if (n & 1) { memcpy(lv[n], lv[n - 1], 32); n++; } memcpy(br[d++], lv[idx ^ 1], 32);
        for (int i = 0; i < n / 2; i++) { uint8_t b[64]; memcpy(b, lv[2 * i], 32); memcpy(b + 32, lv[2 * i + 1], 32); dsha(b, 64, lv[i]); } n /= 2; idx >>= 1; }
    return d;
}
static FILE *REL;
static uint32_t mine(void) {                                  /* one block with whatever is in the mempool */
    uint32_t i = NH++; uint8_t *h = HDR[i]; uint8_t prev[32];
    if (i) dsha(HDR[i - 1], 80, prev); else memset(prev, 0, 32);
    BNT[i] = 1; uint8_t cb[8]; wr32(cb, i); wr32(cb + 4, 0xC0FFEE); dsha(cb, 8, BTX[i][0]);
    for (int m = 0; m < NMEM && BNT[i] < MAXTX; m++) {
        raw_txid(MEM[m], MEML[m], BTX[i][BNT[i]++]);
        fprintf(REL, "%u ", BASE + i); for (size_t k = 0; k < MEML[m]; k++) fprintf(REL, "%02x", MEM[m][k]); fprintf(REL, "\n");
    }
    NMEM = 0;
    memset(h, 0, 80); wr32(h, 4); memcpy(h + 4, prev, 32); merkle_levels(BTX[i], BNT[i], h + 36);
    wr32(h + 68, 1760000000u + i * 600u); wr32(h + 72, 0x207fffff);
    for (uint32_t n = 0;; n++) { uint8_t hh[32]; wr32(h + 76, n); dsha(h, 80, hh); if (!(hh[31] & 0x80)) break; }
    return BASE + i;
}
static int feed(uint32_t height) { uint8_t in[81]; memcpy(in, HDR[height - BASE], 80); in[80] = 1; g_ms += 600000u; return em_header(in); }
static int stage(const uint8_t *d, size_t n) {
    if (em_stage_begin((uint16_t)n)) return -1;
    for (size_t off = 0, i = 0; off < n; off += 64, i++) { uint8_t c[64] = {0}; memcpy(c, d + off, n - off < 64 ? n - off : 64); if (em_stage_chunk((uint16_t)i, c)) return -1; }
    return 0;
}

/* ── the stand-in ESP32's memory ────────────────────────────────────────── */
static uint8_t BLOB[40][EM_BLOB_MAX]; static size_t BLOBL[40]; static uint32_t NBLOB;
static uint8_t OWNER_SK[32], OWNER_X[32];
static uint8_t SEED[64];

static void status(uint8_t s[EM_STATUS_LEN]) { em_status(s); }
static uint32_t floor_h(void) { uint8_t s[EM_STATUS_LEN]; status(s); return rd32(s + 40); }
static void reboot(void) {
    eh_anchor_t a; memset(&a, 0, sizeof a); a.height = BASE; dsha(HDR[0], 80, a.hash); a.bits = 0x207fffff; a.pstart = rd32(HDR[0] + 68); a.ntimes = 1; a.times[0] = rd32(HDR[0] + 68);
    em_boot(&ENV, &TPE, &a);
    for (uint32_t h = floor_h() + 1; h < BASE + NH; h++) feed(h);    /* the ESP32 re-feeds from the G0's restart point */
}

static int prove(char kind, uint32_t link, uint32_t var, const uint8_t txid[32]) {
    for (uint32_t i = NH; i-- > 0;) for (int t = 1; t < BNT[i]; t++) if (!memcmp(BTX[i][t], txid, 32)) {
        uint8_t p[EM_PROOF_LEN] = {0}, br[8][32]; int d = merkle_branch(BTX[i], BNT[i], t, br);
        p[0] = (uint8_t)kind; p[1] = (uint8_t)link; p[2] = (uint8_t)var; p[3] = (uint8_t)d; wr32(p + 4, (uint32_t)t);
        memcpy(p + 8, HDR[i], 80); memcpy(p + 88, br, 32 * d);
        stage(p, sizeof p); return em_proof();
    }
    return -999;
}

int main(void) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    printf("Emberwill end to end (command core, simulated chain)\n");
    REL = fopen("/tmp/ember_released.txt", "w");
    memset(FL, 0xFF, sizeof FL);
    for (int i = 0; i < 64; i++) SEED[i] = (uint8_t)(i * 13 + 5);
    CHECK(btc_account(ctx, SEED, 84, &ACCT, NULL, NULL) == 0, "account");
    for (int i = 0; i < 32; i++) OWNER_SK[i] = (uint8_t)(i + 77);
    { secp256k1_keypair kp; secp256k1_xonly_pubkey xp; secp256k1_keypair_create(ctx, &kp, OWNER_SK); secp256k1_keypair_xonly_pub(ctx, &xp, NULL, &kp); secp256k1_xonly_pubkey_serialize(ctx, OWNER_X, &xp); }
    ENV = (em_env_t){ ctx, { f_erase, f_prog, f_map, NULL }, env_ms, env_rand, env_leaf, NULL };

    mine(); reboot();
    for (int i = 0; i < 40; i++) feed(mine());
    uint8_t st[EM_STATUS_LEN]; status(st);
    CHECK(rd32(st + 8) == BASE + 40 && !(st[5] & 1), "synced to %u, no plan", rd32(st + 8));

    /* ── 1. ceremony ── */
    uint8_t w[EP_SET_LEN] = {0}, coin_pub[2][33], k_[32];
    w[0] = 2; w[1] = 2; w[2] = 3;
    for (int c = 0; c < 2; c++) {
        uint8_t *p = w + 4 + 52 * c; for (int i = 0; i < 32; i++) p[i] = (uint8_t)(0x40 + c * 7 + i);
        wr32(p + 32, (uint32_t)c); wr32(p + 36, 50000000u + 1000u * c); wr32(p + 40, 0); wr32(p + 44, (uint32_t)c); wr32(p + 48, 3u + c);
        btc_leaf(ctx, &ACCT, (uint32_t)c, 3u + c, k_, coin_pub[c]);
    }
    uint8_t *h1 = w + 160; h1[0] = 0x00; h1[1] = 0x14; memset(h1 + 2, 0x11, 20); h1[34] = 0x70; h1[35] = 0x17;   /* 6000 bp */
    uint8_t *h2 = w + 196; h2[0] = 0x51; h2[1] = 0x20; memset(h2 + 2, 0x22, 32); h2[34] = 0xA0; h2[35] = 0x0F;   /* 4000 bp */
    w[376] = 0x00; w[377] = 0x14; memset(w + 378, 0x33, 20);
    wr32(w + 410, 4032); wr32(w + 414, 20);
    w[418] = 5; w[420] = 20; w[422] = 80; w[424] = 10; wr32(w + 426, 1000);
    CHECK(em_set(w) == EM_OK, "EMBER_SET");
    uint32_t sigs = 0, bad_rel = 0; int rc;
    for (;;) {
        uint8_t h[32], t[32], r0[33], r[32]; uint16_t k; uint8_t in;
        for (int i = 0; i < 32; i++) t[i] = (uint8_t)(sigs * 31 + i * 7 + 1);
        ae_host_commit(AE_KIND_ECDSA, t, h);
        if ((rc = em_cer_init(h, r0, &k, &in)) != EM_OK) break;
        size_t bl = 0;
        CHECK(em_cer_finish(t, r, BLOB[k], EM_BLOB_MAX, &bl) == EM_OK, "finish sig %u", sigs);
        if (!ae_host_check(ctx, AE_KIND_ECDSA, r0, t, r)) bad_rel++;
        if (bl) { BLOBL[k] = bl; NBLOB = k + 1u > NBLOB ? k + 1u : NBLOB; }
        sigs++;
    }
    CHECK(NBLOB == 15 && bad_rel == 0, "ceremony: %u blobs, %u signatures, %u failed the host relation", NBLOB, sigs, bad_rel);
    CHECK(sigs == 3 * 2 + 2 + 2 + 3 * 3, "signature count %u", sigs);
    CHECK(em_commit() == EM_OK, "commit");
    printf("  ceremony: %u signatures, every one checked by the host relation, %u sealed blobs\n", sigs, NBLOB);
    /* blobs are ciphertext: no input outpoint appears in them */
    int leak = 0; for (uint32_t k = 0; k < NBLOB; k++) for (size_t i = 0; i + 32 <= BLOBL[k]; i++) if (!memcmp(BLOB[k] + i, w + 4, 32)) leak++;
    CHECK(leak == 0, "no plaintext outpoint in any blob");

    reboot(); status(st);
    CHECK((st[5] & 3) == 3 && st[6] == 0 && st[7] == 3, "after reboot: plan + state, link 0 of 3");

    /* tier 3 before the owner key is bound: refused */
    { uint8_t ser[256], id[32]; size_t n;
      CHECK(em_pulse(ser, sizeof ser, &n, id) == EM_E_OWNER, "Pulse before owner bound");
      stage((const uint8_t *)"[0]", 3); uint8_t z[64] = {0}; CHECK(em_life(z) == EM_E_OWNER, "note before owner bound"); }
    em_life_tier1(OWNER_X);      /* first unlock in a Nostr life binds the owner key */
    status(st); CHECK(st[5] & 4, "owner bound");

    /* ── 2..3. the owner lives; refreshes walk the chain ── */
    uint32_t start = BASE + NH - 1, released_r = 0, proofs = 0, die = 0, reboots = 0, refused = 0;
    uint8_t pending_txid[32]; int pending = 0; uint32_t pend_link = 0; char pend_kind = 0; uint32_t pend_var = 0, pend_h = 0;
    uint8_t raw[1100]; size_t rl;
    uint32_t coupon_height = 0, done_height = 0;
    for (uint32_t step = 0; step < 30000; step++) {
        uint32_t tip = mine(); rc = feed(tip);
        CHECK(rc == EH_TIP, "feed %u: %d", tip, rc);
        status(st);
        if (!(st[5] & 1)) { done_height = tip; break; }
        int alive = st[6] < 3 || tip < start + 14500;
        if (!die && !alive) die = tip;
        if (alive && tip % 500 == 0) em_life_tier1(OWNER_X);
        if (alive && tip % 1700 == 0) {                            /* a Pulse built by the G0, signed by the owner, fed back */
            uint8_t ser[256], id[32], sig[64]; size_t n; secp256k1_keypair kp;
            if (em_pulse(ser, sizeof ser, &n, id) == EM_OK) {
                secp256k1_keypair_create(ctx, &kp, OWNER_SK); secp256k1_schnorrsig_sign32(ctx, sig, id, &kp, NULL);
                stage(ser, n); CHECK(em_life(sig) == EM_OK, "Pulse accepted");
            }
        }
        if (step % 2500 == 1249) { reboot(); reboots++; }
        /* proofs once 3 deep (6 for the coupon so the G0 sees it settle) */
        if (pending && pend_h && tip >= pend_h + 2) {
            rc = prove(pend_kind, pend_link, pend_var, pending_txid);
            if (rc == EM_OK) { proofs++; pending = 0; }
        }
        if (pending && !pend_h) for (uint32_t i = NH; i-- > NH - 1;) for (int t = 1; t < BNT[i]; t++) if (!memcmp(BTX[i][t], pending_txid, 32)) pend_h = BASE + i;
        /* what does the G0 allow now? (fresh: a proof above may have moved the walk) */
        status(st);
        uint8_t what = st[44], link = st[45], var = st[46];
        if (what && !pending) {
            ew_release_t r = { what, link, var }; uint32_t k = em_blob_index(r);
            /* refusals first: a different blob, then a tampered one */
            stage(BLOB[(k + 1) % NBLOB], BLOBL[(k + 1) % NBLOB]); { int rr = em_release(raw, sizeof raw, &rl); if (rr == EM_E_BLOB) refused++; else printf("  wrong blob: %d\n", rr); }
            uint8_t tb[EM_BLOB_MAX]; memcpy(tb, BLOB[k], BLOBL[k]); tb[20] ^= 1; stage(tb, BLOBL[k]); if (em_release(raw, sizeof raw, &rl) == EM_E_BLOB) refused++;
            stage(BLOB[k], BLOBL[k]);
            { int rr = em_release(raw, sizeof raw, &rl);
              CHECK(rr == EM_OK, "release %c%u v%u at %u: %d (k %u)", what == 1 ? 'R' : 'C', link, var, tip, rr, k);
              if (rr) { const ew_state_t *ww = em_walk(); ew_release_t nx = ew_next(ww, eh_tip_height(em_chain()));
                printf("    walk: link %u life %u x %u tip %u next %d | st tip %u\n", ww->link, ww->last_life, ew_x(ww, ww->link), eh_tip_height(em_chain()), nx.what, rd32(st + 8)); continue; } }
            raw_txid(raw, rl, pending_txid); pending = 1; pend_h = 0; pend_kind = what == 1 ? 'R' : 'C'; pend_link = link; pend_var = var;
            if (what == 1) released_r++; else if (!coupon_height) coupon_height = tip;
            memcpy(MEM[NMEM], raw, rl); MEML[NMEM++] = rl;
        }
    }
    /* out-of-turn release and a bad proof (on a fresh plan the checks would need a ceremony; use what we have) */
    printf("  walk: %u refreshes released and proved, %u reboots, %u wrong/tampered blobs refused\n", released_r, reboots, refused);
    CHECK(released_r == 3, "all three refreshes walked (%u)", released_r);
    CHECK(refused >= 2 * (released_r + 1), "every wrong or tampered blob refused (%u)", refused);
    CHECK(coupon_height && coupon_height >= die, "coupon after silence (silent from %u, coupon %u)", die, coupon_height);
    status(st);
    CHECK(done_height && !(st[5] & 1), "plan erased after the coupon was 6 deep (at %u)", done_height);
    printf("  owner silent from %u: coupon C3 released at %u (+%u blocks), confirmed, plan erased at %u\n", die, coupon_height, coupon_height - die, done_height);
    { extern unsigned em_dbg_persist[4]; printf("  persists: force %u life %u tip %u ag %u\n", em_dbg_persist[0], em_dbg_persist[1], em_dbg_persist[2], em_dbg_persist[3]); }
    printf("  flash: %d page erases over the whole run\n", erases);
    fclose(REL);
    printf("%d passed, %d failed\n", pass, fail);
    return fail != 0;
}
