/* host_ember_hdr.c — Emberwill header clock + Merkle check on the host.
 * 28 Oct 2026. Run tests/run_ember_hdr.sh from the project root.
 *
 * Mainnet data (no synthetic numbers where real ones exist):
 *   tests/data/mainnet_1_1111.bin   blocks 1..1111 (cloudhead/nakamoto test data);
 *                                   genesis is the well-known header below
 *   tests/data/ember_vectors.h      summa-tx relays + bitcoin-spv mainnet headers,
 *                                   proofs and retargets, Bitcoin Core pow_tests values
 * Synthetic chains (easy regtest-style target, mined here) cover the rules a
 * mainnet header cannot be mutated to exercise without breaking its PoW:
 * wrong nBits, MTP, version, reorg depth and work-not-length fork choice.
 */
#include "ember_hdr.h"
#include "sha256.h"
#include "data/ember_vectors.h"
#include "data/merkle_vectors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static const char *rcname(int rc) {
    switch (rc) { case EH_TIP: return "TIP"; case EH_REORG: return "REORG"; case EH_SIDE: return "SIDE"; case EH_DUP: return "DUP";
    case EH_E_ORPHAN: return "ORPHAN"; case EH_E_POW: return "POW"; case EH_E_BITS: return "BITS"; case EH_E_TIME: return "TIME";
    case EH_E_VER: return "VER"; case EH_E_DEEP: return "DEEP"; } return "?";
}
static void anchor_from(eh_anchor_t *a, const uint8_t h[80], uint32_t height, uint32_t pstart) {
    memset(a, 0, sizeof(*a));
    a->height = height; eh_hash(h, a->hash); a->bits = rd32(h + 72); a->pstart = pstart;
    a->ntimes = 1; a->times[0] = rd32(h + 68);
}
/* The vector sets carry one header before the chain, not the 11 the anchor
 * wants. The ten missing ancestor timestamps are filled with a value below
 * any of them (the period start, or 0): that can only make MTP weaker in
 * these tests, never stricter. The device anchor carries the real eleven. */
static void anchor_pad(eh_anchor_t *a, uint32_t low) {
    uint32_t t = a->times[0];
    if (a->height < 10) return;
    a->ntimes = EH_MTP_SPAN;
    for (int i = 0; i < EH_MTP_SPAN - 1; i++) a->times[i] = low;
    a->times[EH_MTP_SPAN - 1] = t;
}

/* ── consensus arithmetic ───────────────────────────────────────────────── */
static void test_compact(void) {
    /* Bitcoin Core src/test/arith_uint256_tests.cpp, bignum_SetCompact */
    struct { uint32_t in; int ok; uint32_t back; } v[] = {
        {0x00000000, 0, 0}, {0x00123456, 0, 0}, {0x01003456, 0, 0}, {0x02000056, 0, 0}, {0x03000000, 0, 0},
        {0x04000000, 0, 0}, {0x00923456, 0, 0}, {0x01803456, 0, 0}, {0x02800056, 0, 0}, {0x03800000, 0, 0},
        {0x04800000, 0, 0}, {0x01123456, 1, 0x01120000}, {0x02008000, 1, 0x02008000}, {0x05009234, 1, 0x05009234},
        {0x20123456, 1, 0x20123456}, {0x04923456, 0, 0} /* negative */, {0xff123456, 0, 0} /* overflow */,
        {0x1d00ffff, 1, 0x1d00ffff}, {0x207fffff, 1, 0x207fffff}, {0x17371ef4, 1, 0x17371ef4},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint32_t t[8]; int ok = eh_bits_to_target(v[i].in, t);
        CHECK(ok == v[i].ok, "compact 0x%08x ok=%d", v[i].in, ok);
        if (ok && v[i].ok) CHECK(eh_target_to_bits(t) == v[i].back, "compact 0x%08x -> 0x%08x", v[i].in, eh_target_to_bits(t));
    }
    /* work: Core GetBlockProof(0x1d00ffff) == 0x100010001 */
    uint32_t w[8]; eh_work(0x1d00ffff, w);
    CHECK(w[0] == 0x00010001 && w[1] == 1 && !w[2] && !w[3] && !w[7], "work(0x1d00ffff) = %08x%08x", w[1], w[0]);
}

static void test_retarget(void) {
    for (size_t i = 0; i < sizeof RT_VECS / sizeof RT_VECS[0]; i++) {
        const rt_vec_t *r = &RT_VECS[i];
        uint32_t got = eh_retarget(&EH_MAINNET, r->bits, r->first, r->last);
        CHECK(got == r->next, "retarget %s h=%u: 0x%08x != 0x%08x", r->src, r->height, got, r->next);
    }
    printf("  retarget: %zu mainnet vectors\n", sizeof RT_VECS / sizeof RT_VECS[0]);
}

/* ── mainnet from genesis ───────────────────────────────────────────────── */
static const uint8_t GENESIS[80] = {
    0x01,0x00,0x00,0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
    0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
    0x29,0xab,0x5f,0x49, 0xff,0xff,0x00,0x1d, 0x1d,0xac,0x2b,0x7c };
static uint8_t *load(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(*n); if (fread(b, 1, *n, f) != *n) { free(b); b = NULL; } fclose(f); return b;
}
static void test_genesis_run(void) {
    size_t n; uint8_t *f = load("tests/data/mainnet_1_1111.bin", &n);
    CHECK(f && n % 80 == 0, "load mainnet_1_1111.bin"); if (!f) return;
    size_t cnt = n / 80 + 1;                      /* b[i] is block i */
    uint8_t *b = malloc(80 * cnt); memcpy(b, GENESIS, 80); memcpy(b + 80, f, n); free(f);
    static const uint8_t GENESIS_ID[32] = { /* 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f, reversed */
        0x6f,0xe2,0x8c,0x0a,0xb6,0xf1,0xb3,0x72,0xc1,0xa6,0xa2,0x46,0xae,0x63,0xf7,0x4f,
        0x93,0x1e,0x83,0x65,0xe1,0x5a,0x08,0x9c,0x68,0xd6,0x19,0x00,0x00,0x00,0x00,0x00 };
    uint8_t gh[32]; eh_hash(b, gh);
    CHECK(memcmp(gh, GENESIS_ID, 32) == 0, "genesis hash");
    eh_anchor_t a; anchor_from(&a, b, 0, rd32(b + 68));
    static eh_chain_t c; eh_init(&c, &EH_MAINNET, &a);
    int bad = 0;
    for (size_t i = 1; i < cnt; i++) {
        int rc = eh_connect(&c, b + 80 * i);
        if (rc != EH_TIP) { if (bad++ < 3) printf("  block %zu: %s\n", i, rcname(rc)); }
    }
    CHECK(bad == 0, "%d of %zu mainnet headers refused", bad, cnt - 1);
    uint8_t lh[32]; eh_hash(b + 80 * (cnt - 1), lh);
    CHECK(eh_tip_height(&c) == cnt - 1 && memcmp(eh_tip(&c)->hash, lh, 32) == 0, "tip after %zu", cnt - 1);
    printf("  mainnet 1..%zu: all accepted, tip %u\n", cnt - 1, eh_tip_height(&c));

    /* every single-bit flip of a real header is refused, and leaves the tip alone */
    eh_init(&c, &EH_MAINNET, &a);
    for (size_t i = 1; i <= 500; i++) eh_connect(&c, b + 80 * i);
    uint8_t h[80]; int flips = 0, refused = 0;
    for (int bit = 0; bit < 640; bit++) {
        memcpy(h, b + 80 * 501, 80); h[bit / 8] ^= 1u << (bit % 8);
        int rc = eh_connect(&c, h); flips++;
        if (rc < 0) refused++; else printf("  bit %d accepted: %s\n", bit, rcname(rc));
        if (eh_tip_height(&c) != 500) { printf("  tip moved on bit %d\n", bit); break; }
    }
    CHECK(refused == flips, "bit flips: %d of %d refused", refused, flips);
    printf("  block 501: %d single-bit mutations, all refused, tip unmoved\n", flips);
    CHECK(eh_connect(&c, b + 80 * 501) == EH_TIP, "real 501 after flips");
    CHECK(eh_connect(&c, b + 80 * 501) == EH_DUP, "501 again is DUP");
    CHECK(eh_connect(&c, b + 80 * 490) == EH_DUP, "490 again is DUP (still in the ring)");
    CHECK(eh_connect(&c, b + 80 * 300) == EH_E_ORPHAN, "300 again: parent long out of the ring, ORPHAN");
    CHECK(eh_connect(&c, b + 80 * 503) == EH_E_ORPHAN, "503 without 502 is ORPHAN");
    free(b);
}

/* ── mainnet across retargets, with real stale blocks ───────────────────── */
static void test_chain_a(void) {
    static eh_chain_t c; eh_anchor_t a; int n = sizeof A_CHAIN / 80;
    /* order 1: stale block first, then the real branch overtakes it (a real mainnet reorg) */
    anchor_from(&a, A_ANCHOR[0], A_HEIGHT, A_PSTART); anchor_pad(&a, A_PSTART); eh_init(&c, &EH_MAINNET, &a);
    int k = A_STALE_HEIGHT - A_HEIGHT - 1;          /* index of the real block at the stale height */
    for (int i = 0; i < k; i++) { int rc = eh_connect(&c, A_CHAIN[i]); CHECK(rc == EH_TIP, "A %u: %s", A_HEIGHT + 1 + i, rcname(rc)); }
    CHECK(A_HEIGHT < 437472 && A_HEIGHT + n >= 437472, "chain A crosses the 437472 retarget");
    CHECK(rd32(A_CHAIN[437472 - A_HEIGHT - 1] + 72) != rd32(A_CHAIN[437471 - A_HEIGHT - 1] + 72), "bits changed at 437472");
    int rc = eh_connect(&c, A_STALE[0]);           CHECK(rc == EH_TIP, "stale %u first: %s", A_STALE_HEIGHT, rcname(rc));
    rc = eh_connect(&c, A_CHAIN[k]);               CHECK(rc == EH_SIDE, "real %u second (tie): %s", A_STALE_HEIGHT, rcname(rc));
    uint8_t st[32]; eh_hash(A_STALE[0], st);
    CHECK(memcmp(eh_tip(&c)->hash, st, 32) == 0, "tie keeps first seen");
    rc = eh_connect(&c, A_CHAIN[k + 1]);           CHECK(rc == EH_REORG, "real %u: %s", A_STALE_HEIGHT + 1, rcname(rc));
    CHECK(eh_last_fork(&c) == A_STALE_HEIGHT - 1, "fork height %u", eh_last_fork(&c));
    CHECK(eh_find_main(&c, st, NULL) == 0, "stale block no longer on main");
    for (int i = k + 2; i < n; i++) { rc = eh_connect(&c, A_CHAIN[i]); CHECK(rc == EH_TIP, "A %u: %s", A_HEIGHT + 1 + i, rcname(rc)); }
    uint8_t th[32]; eh_hash(A_CHAIN[n - 1], th);
    CHECK(eh_tip_height(&c) == A_HEIGHT + n && memcmp(eh_tip(&c)->hash, th, 32) == 0, "A tip");
    /* order 2: real first, stale later stays a side branch */
    eh_init(&c, &EH_MAINNET, &a);
    for (int i = 0; i < n; i++) eh_connect(&c, A_CHAIN[i]);
    rc = eh_connect(&c, A_STALE[0]);               CHECK(rc == EH_SIDE, "stale after real: %s", rcname(rc));
    CHECK(memcmp(eh_tip(&c)->hash, th, 32) == 0, "tip unchanged by stale");
    /* the retarget block with a period start 10 minutes off is refused */
    a.pstart = A_PSTART + 600; eh_init(&c, &EH_MAINNET, &a);
    for (int i = 0; i < (int)(437472 - A_HEIGHT - 1); i++) eh_connect(&c, A_CHAIN[i]);
    rc = eh_connect(&c, A_CHAIN[437472 - A_HEIGHT - 1]);
    CHECK(rc == EH_E_BITS, "437472 with period start +600 s: %s", rcname(rc));
    printf("  chain A %u..%u: retarget at 437472 exact, real stale block at %u reorged out (both orders)\n", A_HEIGHT + 1, A_HEIGHT + n, A_STALE_HEIGHT);
}

static void test_chain_b(void) {
    static eh_chain_t c; eh_anchor_t a; int n = sizeof B_CHAIN / 80;
    anchor_from(&a, B_ANCHOR[0], B_HEIGHT, 0); anchor_pad(&a, 0); eh_init(&c, &EH_MAINNET, &a);
    int k = B_STALE_HEIGHT - B_HEIGHT - 1;
    for (int i = 0; i < k; i++) eh_connect(&c, B_CHAIN[i]);
    int r1 = eh_connect(&c, B_STALE[0]), r2 = eh_connect(&c, B_STALE[1]), r3 = eh_connect(&c, B_CHAIN[k]), r4 = eh_connect(&c, B_CHAIN[k + 1]);
    /* B_STALE[1] ("badHeader" in the source) has real PoW but a parent off this chain */
    CHECK(r1 == EH_TIP && r2 == EH_E_ORPHAN && r3 == EH_SIDE && r4 == EH_REORG, "B three-way at %u: %s %s %s %s", B_STALE_HEIGHT, rcname(r1), rcname(r2), rcname(r3), rcname(r4));
    for (int i = k + 2; i < n; i++) { int rc = eh_connect(&c, B_CHAIN[i]); CHECK(rc == EH_TIP, "B %u: %s", B_HEIGHT + 1 + i, rcname(rc)); }
    uint8_t th[32]; eh_hash(B_CHAIN[n - 1], th);
    CHECK(eh_tip_height(&c) == B_HEIGHT + n && memcmp(eh_tip(&c)->hash, th, 32) == 0, "B tip");
    printf("  chain B %u..%u: two competing blocks at %u plus a stray, heaviest branch wins\n", B_HEIGHT + 1, B_HEIGHT + n, B_STALE_HEIGHT);
}

static void test_chain_c(void) {
    static eh_chain_t c; eh_anchor_t a;
    anchor_from(&a, C_ANCHOR[0], C_HEIGHT, C_PSTART); anchor_pad(&a, C_PSTART); eh_init(&c, &EH_MAINNET, &a);
    for (size_t i = 0; i < sizeof C_CHAIN / 80; i++) { int rc = eh_connect(&c, C_CHAIN[i]); CHECK(rc == EH_TIP, "C %zu: %s", C_HEIGHT + 1 + i, rcname(rc)); }
    printf("  chain C: retarget at 306432 accepted\n");
}

/* ── Merkle ─────────────────────────────────────────────────────────────── */
static void rev(uint8_t *d, const uint8_t *s) { for (int i = 0; i < 32; i++) d[i] = s[31 - i]; }
static void test_merkle(void) {
    for (size_t i = 0; i < sizeof MK_VECS / sizeof MK_VECS[0]; i++) {
        const mk_vec_t *v = &MK_VECS[i]; const uint8_t *root = v->hdr + 36;
        uint8_t t2[32]; rev(t2, v->txid);
        int ok = eh_merkle_check(v->txid, v->index, v->depth, v->nodes, root);
        int okr = eh_merkle_check(t2, v->index, v->depth, v->nodes, root);
        CHECK(ok ^ okr, "%s: exactly one byte order verifies (%d %d)", v->src, ok, okr);
        const uint8_t *tx = ok ? v->txid : t2;
        uint8_t nodes[20][32]; memcpy(nodes, v->nodes, sizeof nodes);
        int caught = 0, tries = 0;
        for (int d = 0; d < v->depth; d++) for (int bit = 0; bit < 256; bit += 37) {
            nodes[d][bit / 8] ^= 1u << (bit % 8);
            caught += !eh_merkle_check(tx, v->index, v->depth, nodes, root); tries++;
            nodes[d][bit / 8] ^= 1u << (bit % 8);
        }
        CHECK(caught == tries, "%s: node mutations %d/%d caught", v->src, caught, tries);
        CHECK(!eh_merkle_check(tx, v->index ^ 1, v->depth, v->nodes, root), "%s: wrong index", v->src);
        CHECK(!eh_merkle_check(tx, v->index | (1u << v->depth), v->depth, v->nodes, root), "%s: index beyond depth", v->src);
        CHECK(!eh_merkle_check(tx, v->index, v->depth - 1, v->nodes, root), "%s: short branch", v->src);
        CHECK(!eh_merkle_check(tx, v->index, 21, v->nodes, root), "%s: depth 21", v->src);
        printf("  merkle %s: depth %d index %u verifies against the real header\n", v->src, v->depth, v->index);
    }
    /* independent Python construction: real early-mainnet blocks + trees of 1..4097 leaves */
    { size_t n = sizeof MK_GEN / sizeof MK_GEN[0]; int bad = 0, pos = 0;
      for (size_t i = 0; i < n; i++) {
          const mk_gen_t *v = &MK_GEN[i];
          int ok = eh_merkle_check(v->leaf, v->index, v->depth, v->nodes, v->root);
          if (ok != v->ok) { if (bad++ < 5) printf("  MK_GEN[%zu] depth %d index %u: %d want %d\n", i, v->depth, v->index, ok, v->ok); }
          pos += v->ok;
      }
      CHECK(bad == 0, "MK_GEN: %d of %zu wrong", bad, n);
      printf("  merkle: %zu independent vectors (%d real mainnet txs, %d should verify) all agree\n", n, MK_GEN_REAL, pos); }
    for (size_t i = 0; i < sizeof MK_RAW / sizeof MK_RAW[0]; i++) {
        const mk_raw_t *v = &MK_RAW[i]; if (v->len < 2) continue;
        uint8_t depth = v->len - 2;
        int ok = eh_merkle_check(v->buf, v->index, depth, (const uint8_t (*)[32])(v->buf + 32), v->buf + 32 * (v->len - 1));
        CHECK(ok == v->ok, "verifyHash256Merkle[%zu] len %d index %u: %d want %d", i, v->len, v->index, ok, v->ok);
    }
}

/* ── synthetic chains: the rules a real header can't be bent to show ────── */
static const eh_params_t TP = {
    .pow_limit = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x0007FFFFu },
    .interval = 16, .timespan = 16 * 60,   /* limit * 4 * timespan < 2^256, as on mainnet */ .no_retarget = 0, .v2_height = 0, .v3_height = 0, .v4_height = 0,
};
static uint32_t g_salt;
/* Mines a header on prev with the given time and bits (nonce search). */
static void mine(uint8_t h[80], const uint8_t prev[32], uint32_t time, uint32_t bits, int32_t ver) {
    memset(h, 0, 80); wr32(h, (uint32_t)ver); memcpy(h + 4, prev, 32);
    wr32(h + 36, ++g_salt); wr32(h + 68, time); wr32(h + 72, bits);
    uint32_t t[8]; eh_bits_to_target(bits, t);
    for (uint32_t nonce = 0;; nonce++) {
        wr32(h + 76, nonce); uint8_t hh[32]; eh_hash(h, hh);
        int le = 1; for (int i = 7; i >= 0; i--) { uint32_t x = rd32(hh + 4 * i); if (x != t[i]) { le = x < t[i]; break; } }
        if (le) return;
    }
}
/* expected next bits on branch with tip at height th */
typedef struct { uint8_t hash[64][32]; uint32_t time[64], bits[64], pstart[64]; } shadow_t;
static uint32_t next_bits(const shadow_t *s, uint32_t ph) {
    if ((ph + 1) % TP.interval) return s->bits[ph];
    return eh_retarget(&TP, s->bits[ph], s->pstart[ph], s->time[ph]);
}
static int add(eh_chain_t *c, shadow_t *s, uint32_t ph, uint32_t time, uint8_t out[80]) {
    uint8_t h[80]; uint32_t b = next_bits(s, ph);
    mine(h, s->hash[ph], time, b, 4);
    int rc = eh_connect(c, h);
    if (rc >= 0) { uint32_t n = ph + 1; eh_hash(h, s->hash[n]); s->time[n] = time; s->bits[n] = b; s->pstart[n] = (n % TP.interval) ? s->pstart[ph] : time; }
    if (out) memcpy(out, h, 80);
    return rc;
}
static void syn_init(eh_chain_t *c, shadow_t *s, uint32_t t0) {
    uint8_t g[80], z[32] = {0}; mine(g, z, t0, 0x1f07ffff, 4);
    eh_anchor_t a; anchor_from(&a, g, 0, t0); eh_init(c, &TP, &a);
    memset(s, 0, sizeof *s); eh_hash(g, s->hash[0]); s->time[0] = t0; s->bits[0] = 0x1f07ffff; s->pstart[0] = t0;
}

static void test_synthetic(void) {
    static eh_chain_t c; static shadow_t s, f; uint32_t T0 = 1700000000; int rc; uint8_t h[80];

    /* 1. retarget clamps: a 4x-fast period makes the next target exactly 1/4 */
    syn_init(&c, &s, T0);
    for (uint32_t i = 1; i <= 15; i++) CHECK(add(&c, &s, i - 1, T0 + i * 15, NULL) == EH_TIP, "fast %u", i);
    uint32_t want = next_bits(&s, 15);
    CHECK(want == 0x1f01ffff, "fast period -> 0x%08x", want);
    mine(h, s.hash[15], T0 + 16 * 15, 0x1f07ffff, 4);                       /* keeps the old bits */
    rc = eh_connect(&c, h); CHECK(rc == EH_E_BITS || rc == EH_E_POW, "boundary with stale bits: %s", rcname(rc));
    if (rc == EH_E_POW) printf("  (stale-bits header failed PoW first; acceptable)\n");
    CHECK(add(&c, &s, 15, T0 + 16 * 15, NULL) == EH_TIP, "boundary with retargeted bits");
    /* bits must not change inside a period */
    mine(h, s.hash[16], T0 + 17 * 15, 0x1f01fffe, 4);
    rc = eh_connect(&c, h); CHECK(rc == EH_E_BITS, "mid-period bits change: %s", rcname(rc));

    /* 2. median time past: equal to MTP refused, MTP+1 accepted */
    for (uint32_t i = 17; i <= 30; i++) add(&c, &s, i - 1, T0 + i * 60, NULL);
    uint32_t mtp = eh_tip_mtp(&c);
    mine(h, s.hash[30], mtp, next_bits(&s, 30), 4);
    rc = eh_connect(&c, h); CHECK(rc == EH_E_TIME, "time == MTP: %s", rcname(rc));
    mine(h, s.hash[30], mtp - 1000, next_bits(&s, 30), 4);
    rc = eh_connect(&c, h); CHECK(rc == EH_E_TIME, "time < MTP: %s", rcname(rc));
    rc = add(&c, &s, 30, mtp + 1, NULL); CHECK(rc == EH_TIP, "time == MTP+1: %s", rcname(rc));
    /* a header 10 years in the future is accepted: no clock, by design (it still costs PoW) */
    rc = add(&c, &s, 31, T0 + 315360000u, NULL); CHECK(rc == EH_TIP, "far-future time: %s", rcname(rc));

    /* 3. version: below 4 refused once BIP65 height is reached; negative refused */
    mine(h, s.hash[32], T0 + 33 * 60 + 315360000u, next_bits(&s, 32), 3);
    rc = eh_connect(&c, h); CHECK(rc == EH_E_VER, "version 3: %s", rcname(rc));
    mine(h, s.hash[32], T0 + 33 * 60 + 315360000u, next_bits(&s, 32), (int32_t)0x80000004);
    rc = eh_connect(&c, h); CHECK(rc == EH_E_VER, "negative version: %s", rcname(rc));

    /* 4. reorg depth: build 40 blocks at steady 600 s, then fork at every depth */
    syn_init(&c, &s, T0);
    for (uint32_t i = 1; i <= 40; i++) add(&c, &s, i - 1, T0 + i * 60, NULL);
    for (uint32_t d = 1; d <= 26; d++) {
        static eh_chain_t c2; c2 = c; f = s;
        uint32_t fp = 40 - d;
        rc = add(&c2, &f, fp, T0 + (fp + 1) * 60, NULL);
        int want_rc = d <= EH_RING - EH_MTP_SPAN ? EH_SIDE : (d < EH_RING ? EH_E_DEEP : EH_E_ORPHAN);
        CHECK(rc == want_rc, "fork at depth %u: %s want %s", d, rcname(rc), rcname(want_rc));
        if (rc == EH_SIDE) {
            int r = EH_SIDE; uint32_t ph = fp + 1;
            while (r == EH_SIDE) { r = add(&c2, &f, ph, T0 + (ph + 1) * 60, NULL); ph++; }
            CHECK(r == EH_REORG && ph == 41 && eh_last_fork(&c2) == fp, "depth %u: reorg after %u blocks (%s)", d, ph - fp, rcname(r));
            CHECK(memcmp(eh_tip(&c2)->hash, f.hash[41], 32) == 0, "depth %u: new tip", d);
        }
    }
    printf("  synthetic: reorgs up to depth %d taken, %d..%d refused DEEP, %d+ ORPHAN\n", EH_RING - EH_MTP_SPAN, EH_RING - EH_MTP_SPAN + 1, EH_RING - 1, EH_RING);

    /* 5. a new fork replaces an unfinished candidate; a candidate left 24 behind is dropped */
    { static eh_chain_t c2; c2 = c; f = s; static shadow_t g; g = s;
      CHECK(add(&c2, &f, 38, T0 + 39 * 60 + 1, NULL) == EH_SIDE, "cand 1");
      CHECK(add(&c2, &g, 37, T0 + 38 * 60 + 2, NULL) == EH_SIDE, "cand 2 replaces cand 1");
      rc = add(&c2, &f, 39, T0 + 40 * 60 + 1, NULL);
      CHECK(rc == EH_E_ORPHAN, "extending the replaced cand 1: %s", rcname(rc));
      static shadow_t m; m = s;
      for (uint32_t i = 41; i <= 37 + EH_RING; i++) add(&c2, &m, i - 1, T0 + i * 60, NULL);
      rc = add(&c2, &g, 38, T0 + 39 * 60 + 2, NULL);
      CHECK(rc == EH_E_ORPHAN, "cand 2 after main ran %d past its fork: %s", EH_RING, rcname(rc)); }

    /* 6. work, not length: two branches through a retarget, the shorter one is heavier.
     *    Period 0 runs fast. Main's block 15 is late, so its next target stays at the
     *    limit; the fork's 15' is on time, so its next target is 1/4: one block of 4x work. */
    syn_init(&c, &s, T0);
    for (uint32_t i = 1; i <= 14; i++) add(&c, &s, i - 1, T0 + i * 15, NULL);
    f = s;
    for (uint32_t i = 15; i <= 18; i++) CHECK(add(&c, &s, i - 1, T0 + 10000 + (i - 15) * 60, NULL) == EH_TIP, "main %u", i);
    CHECK(s.bits[16] == 0x1f07ffff && s.bits[18] == 0x1f07ffff, "main boundary bits 0x%08x", s.bits[16]);
    rc = add(&c, &f, 14, T0 + 15 * 15, NULL);  CHECK(rc == EH_SIDE, "fork 15': %s", rcname(rc));
    CHECK(next_bits(&f, 15) == 0x1f01ffff, "fork boundary target is 1/4 (0x%08x)", next_bits(&f, 15));
    rc = add(&c, &f, 15, T0 + 16 * 15, NULL);  CHECK(rc == EH_REORG, "16' (4x work) beats 4 easy blocks: %s", rcname(rc));
    CHECK(eh_tip_height(&c) == 16 && eh_last_fork(&c) == 14, "shorter, heavier branch is main (tip %u)", eh_tip_height(&c));
    printf("  synthetic: clamps, MTP, version, candidate replacement and work-not-length fork choice\n");
}

int main(void) {
    printf("Emberwill header clock, host tests\n");
    test_compact(); test_retarget(); test_genesis_run(); test_chain_a(); test_chain_b(); test_chain_c(); test_merkle(); test_synthetic();
    printf("%d passed, %d failed\n", pass, fail);
    return fail != 0;
}
