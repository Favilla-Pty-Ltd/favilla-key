/* fuzz_ember_hdr.c — randomised block trees fed in random order, with
 * mutations, under ASan + UBSan. 28 Oct 2026. tests/run_fuzz_ember_hdr.sh.
 *
 * Each round mines a random tree of headers on easy test params (forks of
 * random depth, some timestamps below MTP, some bits wrong), then feeds a
 * random mix of: tree headers in random order, repeats, bit-flipped copies
 * and random bytes. After every call it checks:
 *   I1  the main branch in the ring is a real chain: every hashed entry is a
 *       mined tree header and links to the entry below it
 *   I2  the main tip's total work (walked through the tree) never decreases
 *   I3  return code agrees with what happened to the tip (TIP: +1 height,
 *       errors and DUP and SIDE: tip unchanged, REORG: more work)
 *   I4  nothing that is not a tree header ever becomes part of main
 */
#include "ember_hdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXB 700
static uint8_t  H[MAXB][80], HH[MAXB][32];
static int      PAR[MAXB], NB, OKN[MAXB];   /* OKN: honest node (children only grow from these) */
static uint32_t HT[MAXB];
static uint64_t rs;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)rs; }
static uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

static const eh_params_t TP = {
    .pow_limit = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x007FFFFFu },
    .interval = 16, .timespan = 16 * 4,   /* 4 s blocks: limit * 4 * timespan < 2^256 with cheap mining */ .v2_height = 0, .v3_height = 0, .v4_height = 0,
};
static int below(const uint8_t hash[32], uint32_t bits) {
    uint32_t t[8]; if (!eh_bits_to_target(bits, t)) return 0;
    for (int i = 7; i >= 0; i--) { uint32_t x = rd32(hash + 4 * i); if (x != t[i]) return x < t[i]; }
    return 1;
}
static int find(const uint8_t hash[32]) { for (int i = 0; i < NB; i++) if (!memcmp(HH[i], hash, 32)) return i; return -1; }

/* consensus-faithful bookkeeping per tree node (for honest headers) */
static uint32_t TIME[MAXB], BITS[MAXB], PST[MAXB];
static void cw_set(int i);
static void mine_child(int p, uint32_t time, uint32_t bits, int32_t ver) {
    int i = NB++; uint8_t *h = H[i];
    memset(h, 0, 80); wr32(h, (uint32_t)ver); memcpy(h + 4, HH[p], 32); wr32(h + 36, rnd()); wr32(h + 40, i);
    wr32(h + 68, time); wr32(h + 72, bits);
    for (uint32_t n = 0;; n++) { wr32(h + 76, n); eh_hash(h, HH[i]); if (below(HH[i], bits)) break; }
    PAR[i] = p; HT[i] = HT[p] + 1; TIME[i] = time; BITS[i] = bits;
    PST[i] = (HT[i] % TP.interval) ? PST[p] : time;
    cw_set(i);
}
static uint32_t mtp(int p) {
    uint32_t v[11]; int k = 0;
    for (int q = p; q >= 0 && k < 11; q = PAR[q]) { uint32_t x = TIME[q]; int j = k++; while (j > 0 && v[j-1] > x) { v[j] = v[j-1]; j--; } v[j] = x; }
    return v[k / 2];
}
static uint32_t CW[MAXB][8];                          /* total work from the anchor, cached */
static void work_of(int i, uint32_t w[8]) { memcpy(w, CW[i], 32); }
static void cw_set(int i) {
    uint32_t x[8]; eh_work(BITS[i], x); uint64_t c = 0;
    for (int k = 0; k < 8; k++) { c += (uint64_t)(i ? CW[PAR[i]][k] : 0) + x[k]; CW[i][k] = (uint32_t)c; c >>= 32; }
}
static int cmp8(const uint32_t a[8], const uint32_t b[8]) { for (int i = 7; i >= 0; i--) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1; return 0; }

static long calls, fails, rcn[16], adopted;
static int known(const eh_chain_t *c, const uint8_t hash[32]) {
    if (eh_find_main(c, hash, NULL)) return 1;
    if (!c->cand.live) return 0;
    for (uint32_t i = 0; i < c->cand.n; i++) if (!memcmp(c->cand.r[(c->cand.tip - i) % EH_RING].hash, hash, 32)) return 1;
    return 0;
}
#define INV(c, ...) do { if (!(c)) { fails++; if (fails < 10) { printf("INVARIANT %s: ", #c); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static void round_(void) {
    NB = 0;
    /* anchor */
    { uint8_t *h = H[0]; memset(h, 0, 80); wr32(h, 4); wr32(h + 36, rnd()); wr32(h + 68, 1700000000); wr32(h + 72, 0x1f7fffff);
      for (uint32_t n = 0;; n++) { wr32(h + 76, n); eh_hash(h, HH[0]); if (below(HH[0], 0x1f7fffff)) break; }
      PAR[0] = -1; HT[0] = 0; TIME[0] = 1700000000; BITS[0] = 0x1f7fffff; PST[0] = 1700000000; NB = 1; OKN[0] = 1; memset(CW[0], 0, 32); }
    int tip = 0, target = 60 + rnd() % 300;
    while (NB < target) {
        int p = tip;
        uint32_t r = rnd() % 100;
        if (r < 25) { int back = rnd() % 16; while (back-- && PAR[p] >= 0) p = PAR[p]; }   /* fork */
        while (!OKN[p]) p = PAR[p];
        uint32_t want = BITS[p];
        if ((HT[p] + 1) % TP.interval == 0) want = eh_retarget(&TP, BITS[p], PST[p], TIME[p]);
        uint32_t m = mtp(p), t = TIME[p] + 2 + rnd() % 5;                /* ~4 s: difficulty stays put */
        if (rnd() % 100 < 15) t = TIME[p] + 1;                            /* fast */
        if (rnd() % 100 < 5)  t = TIME[p] + 200;                          /* slow */
        if (t <= m) t = m + 1 + rnd() % 3;
        if (rnd() % 100 < 3) t = m - rnd() % 3;                           /* bad time */
        uint32_t bits = want; if (rnd() % 100 < 3) bits = want ^ (1u << (rnd() % 16)); /* bad bits */
        int32_t ver = rnd() % 100 < 2 ? 3 : 4;                            /* bad version */
        uint32_t tt[8]; if (!eh_bits_to_target(bits, tt) || cmp8(tt, TP.pow_limit) > 0) bits = want;
        mine_child(p, t, bits, ver);
        OKN[NB - 1] = (bits == want && t > m && ver >= 4);
        if (OKN[NB - 1] && HT[NB - 1] > HT[tip]) tip = NB - 1;
    }

    static eh_chain_t c; eh_anchor_t a; memset(&a, 0, sizeof a);
    a.height = 0; memcpy(a.hash, HH[0], 32); a.bits = BITS[0]; a.pstart = PST[0]; a.ntimes = 1; a.times[0] = TIME[0];
    eh_init(&c, &TP, &a);
    uint32_t best[8] = {0};
    int feeds = NB * 4;
    for (int k = 0; k < feeds; k++) {
        uint8_t h[80]; int src = -1; uint32_t r = rnd() % 100;
        if (r < 50) {                    /* the next header on the way to a random node: real progress */
            src = 1 + rnd() % (NB - 1);
            while (PAR[src] > 0 && !known(&c, HH[PAR[src]])) src = PAR[src];
            memcpy(h, H[src], 80);
        }
        else if (r < 70) { src = 1 + rnd() % (NB - 1); memcpy(h, H[src], 80); }
        else if (r < 90) { src = 1 + rnd() % (NB - 1); memcpy(h, H[src], 80); int nf = 1 + rnd() % 3; while (nf--) h[rnd() % 80] ^= 1u << (rnd() % 8); }
        else { for (int i = 0; i < 80; i++) h[i] = rnd(); if (rnd() & 1) memcpy(h + 4, HH[rnd() % NB], 32); }
        uint32_t ht0 = eh_tip_height(&c); uint8_t tip0[32]; memcpy(tip0, eh_tip(&c)->hash, 32);
        int rc = eh_connect(&c, h); calls++; rcn[rc + 8]++;
        /* With easy test targets a mutated copy can be a genuinely valid header (about 1 in
         * 512 flips still meets PoW). Accepting one is correct only if it really satisfies
         * every rule: re-check it independently and adopt it into the tree. */
        if (rc >= 0 && rc != EH_DUP && !(src >= 0 && !memcmp(h, H[src], 80))) {
            uint8_t hh[32]; eh_hash(h, hh); int p = find(h + 4); uint32_t bits = rd32(h + 72), t = rd32(h + 68);
            int ok = p >= 0 && OKN[p] && below(hh, bits) && (int32_t)rd32(h) >= 4 && t > mtp(p);
            if (ok) { uint32_t want = BITS[p]; if ((HT[p] + 1) % TP.interval == 0) want = eh_retarget(&TP, BITS[p], PST[p], TIME[p]); ok = bits == want; }
            INV(ok, "accepted an invalid header (rc %d)", rc);
            if (ok && NB < MAXB) { int i = NB++; memcpy(H[i], h, 80); memcpy(HH[i], hh, 32); PAR[i] = p; HT[i] = HT[p] + 1;
                TIME[i] = t; BITS[i] = bits; PST[i] = (HT[i] % TP.interval) ? PST[p] : t; OKN[i] = 1; cw_set(i); src = i; adopted++; }
        }
        int ti = find(eh_tip(&c)->hash);
        INV(ti >= 0, "tip not a tree header (rc %d)", rc);                                    /* I4 */
        if (ti < 0) return;
        /* I1: ring is a linked chain of tree headers */
        for (uint32_t i = 0; i + 1 < c.main.n; i++) {
            uint32_t hh = c.main.tip - i; const eh_ent_t *e = &c.main.r[hh % EH_RING], *e2 = &c.main.r[(hh - 1) % EH_RING];
            int q = find(e->hash);
            INV(q >= 0 && HT[q] == hh, "ring entry %u not a tree header at its height", hh);
            if (q > 0 && find(e2->hash) >= 0) INV(!memcmp(H[q] + 4, e2->hash, 32), "ring %u does not link to %u", hh, hh - 1);
        }
        uint32_t w[8]; work_of(ti, w);
        INV(cmp8(w, best) >= 0, "tip work decreased (rc %d)", rc);                           /* I2 */
        /* I3 */
        if (rc == EH_TIP) INV(eh_tip_height(&c) == ht0 + 1 && !memcmp(H[ti] + 4, tip0, 32), "TIP but tip did not extend");
        else if (rc == EH_REORG) INV(cmp8(w, best) > 0, "REORG without more work");
        else INV(!memcmp(eh_tip(&c)->hash, tip0, 32), "rc %d moved the tip", rc);
        memcpy(best, w, 32);
    }
}

int main(int argc, char **argv) {
    long rounds = argc > 1 ? atol(argv[1]) : 300;
    rs = argc > 2 ? strtoull(argv[2], 0, 10) : 0x28102026ULL;
    for (long r = 0; r < rounds; r++) round_();
    printf("fuzz_ember_hdr: %ld rounds, %ld eh_connect calls, %ld invariant failures (%ld valid mutants adopted)\n", rounds, calls, fails, adopted);
    printf("  TIP %ld REORG %ld SIDE %ld DUP %ld | ORPHAN %ld POW %ld BITS %ld TIME %ld VER %ld DEEP %ld\n",
           rcn[8], rcn[9], rcn[10], rcn[11], rcn[7], rcn[6], rcn[5], rcn[4], rcn[3], rcn[2]);
    return fails != 0;
}
