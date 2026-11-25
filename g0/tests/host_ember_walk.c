/* host_ember_walk.c — chain-walk scenarios over simulated years. 28 Oct 2026.
 * One step = one block = 600 s of powered time unless the box is "dark".
 * tests/run_ember_walk.sh. */
#include "ember_walk.h"
#include <stdio.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* simulated chain: block hash = height + a branch tag; a "reorg" retags heights >= r */
typedef struct { uint32_t tip; uint32_t reorg_from; uint8_t tag; } sim_t;
static void bh(uint32_t h, uint8_t tag, uint8_t out[32]) { memset(out, 0, 32); memcpy(out, &h, 4); out[4] = tag; out[5] = 0xEE; }
static uint32_t conf_fn(void *ctx, const uint8_t hash[32]) {
    sim_t *s = ctx; uint32_t h; memcpy(&h, hash, 4);
    if (hash[5] != 0xEE || h > s->tip || s->tip - h >= 24) return 0;
    uint8_t want = h >= s->reorg_from ? s->tag : 0;
    return hash[4] == want ? s->tip - h + 1 : 0;
}

#define Q      13140u     /* ~91 days */
#define TIP0   900000u
#define NL     8u

typedef struct {
    ew_state_t w; sim_t sim;
    uint32_t pending_r_conf;     /* height the released refresh confirms in (0 none) */
    uint32_t pending_r_idx;
    int refreshes, coupons, last_var; uint32_t coupon_height, first_coupon_height, done_height;
    int dark;                    /* box off: no ticks */
    int quorum;
    int stuck;                   /* released refreshes never confirm (fee spike) */
} world_t;

static void world_init(world_t *W) {
    memset(W, 0, sizeof *W);
    ew_init(&W->w, NL, Q, TIP0 + Q + 1008, TIP0);
    W->sim.tip = TIP0; W->quorum = 1; W->last_var = -1;
}
/* one block: tip+1, tick, re-check, proofs, and act on releases like an honest ESP32 */
static void step(world_t *W) {
    W->sim.tip++; uint32_t tip = W->sim.tip;
    if (!W->dark) ew_tick(&W->w, 600, W->quorum, tip);
    ew_on_tip(&W->w, tip, conf_fn, &W->sim);
    if (W->pending_r_conf && tip >= W->pending_r_conf + 2) {           /* 3 deep: send the proof */
        uint8_t b[32]; bh(W->pending_r_conf, 0, b);
        if (ew_proof(&W->w, 'R', W->pending_r_idx, b, tip - W->pending_r_conf + 1, W->pending_r_conf)) W->refreshes++;
        W->pending_r_conf = 0;
    }
    if (W->dark) return;
    ew_release_t r = ew_next(&W->w, tip);
    if (r.what == EW_REFRESH && !W->pending_r_conf) {
        CHECK(tip >= ew_x(&W->w, r.link - 1) - Q / 2, "refresh %u released before its locktime window", r.link);
        ew_released(&W->w, r, tip);
        if (!W->stuck) { W->pending_r_conf = tip + 1; W->pending_r_idx = r.link; }   /* confirms next block */
    } else if (r.what == EW_COUPON && (int)r.var != W->last_var) {
        CHECK(tip >= ew_x(&W->w, r.link), "coupon C%u released before X (tip %u X %u)", r.link, tip, ew_x(&W->w, r.link));
        ew_released(&W->w, r, tip); W->coupons++; W->last_var = (int)r.var; W->coupon_height = tip;
        if (!W->first_coupon_height) W->first_coupon_height = tip;
    }
}

static void s1_alive(void) {
    world_t W; world_init(&W);
    for (uint32_t i = 0; i < 2 * 365 * 144; i++) {                   /* two years, PIN monthly */
        if (i % 4320 == 0) ew_life(&W.w, EW_LIFE_TIER1, W.sim.tip, W.sim.tip);
        step(&W);
    }
    CHECK(W.coupons == 0, "alive owner: no coupon ever (%d)", W.coupons);
    CHECK(W.w.link >= 7, "alive owner: chain walked to link %u in two years", W.w.link);
    printf("  alive 2 years, PIN monthly: walked to link %u, %d refreshes, no coupon\n", W.w.link, W.refreshes);
}

static uint32_t worst;
static void s2_dies(uint32_t die_after, const char *what) {
    world_t W; world_init(&W); uint32_t D = 0;
    for (uint32_t i = 0; i < 6 * 365 * 144 && !W.w.done; i++) {
        if (i <= die_after && i % 4320 == 0) { ew_life(&W.w, EW_LIFE_TIER1, W.sim.tip, W.sim.tip); D = W.sim.tip; }
        step(&W);
        if (W.coupons && !W.done_height && W.sim.tip == W.coupon_height + 1) {   /* coupon confirms next block */
            uint8_t b[32]; bh(W.sim.tip, 0, b); ew_proof(&W.w, 'C', W.w.link, b, 1, W.sim.tip); W.done_height = W.sim.tip;
        }
    }
    uint32_t paid = W.first_coupon_height;
    CHECK(W.coupons >= 1 && W.w.done, "%s: coupon released and plan finished", what);
    CHECK(paid >= D + Q + 1008, "%s: paid %u not before last_life + Quiet + 1008 (%u)", what, paid, D + Q + 1008);
    /* r7 states 1.5 Quiet; the rule as written allows 2 Quiet (EMBER_NOTES finding 5):
     * a refresh may still be released up to Quiet/2 after the last life */
    CHECK(paid <= D + 2 * Q + 2, "%s: paid %u within last_life + 2 Quiet (%u)", what, paid, D + 2 * Q);
    if (paid - D > worst) worst = paid - D;
    printf("  %s: last life %u, coupon C%u at %u (+%u blocks = %.0f days)\n", what, D, W.w.link, paid, paid - D, (paid - D) / 144.0);
}

static void s2_dies_quiet(uint32_t die_after) {
    world_t W; world_init(&W); uint32_t D = 0;
    for (uint32_t i = 0; i < 4 * 365 * 144 && !W.coupons; i++) {
        if (i <= die_after && i % 4320 == 0) { ew_life(&W.w, EW_LIFE_TIER1, W.sim.tip, W.sim.tip); D = W.sim.tip; }
        step(&W);
    }
    uint32_t paid = W.first_coupon_height;
    CHECK(W.coupons && paid >= D + Q + 1008 && paid <= D + 2 * Q + 2, "death at %u: paid %u", D, paid);
    if (paid - D > worst) worst = paid - D;
}

static void s3_dark(void) {
    world_t W; world_init(&W); uint32_t D = W.sim.tip;
    W.dark = 1;                                                         /* unplugged right after the ceremony */
    for (uint32_t i = 0; i < 200 * 144; i++) step(&W);                 /* 200 days dark */
    CHECK(ew_silent(&W.w, W.sim.tip) && W.w.ag_secs == 0, "dark: silent, no Afterglow time");
    W.dark = 0; uint32_t on = W.sim.tip;
    while (!W.coupons && W.sim.tip < on + 3000) step(&W);
    CHECK(W.coupons && W.first_coupon_height >= on + 1008, "dark: coupon only after 7 powered days (on %u, coupon %u)", on, W.first_coupon_height);
    printf("  dark box: silent %u days unplugged, coupon %u blocks after power-on (7 powered days)\n", (on - D) / 144, W.first_coupon_height - on);
    /* a living owner who unlocks in those 7 days stops it */
    world_init(&W); W.dark = 1; for (uint32_t i = 0; i < 200 * 144; i++) step(&W);
    W.dark = 0; for (uint32_t i = 0; i < 900; i++) step(&W);
    ew_life(&W.w, EW_LIFE_TIER1, W.sim.tip, W.sim.tip);
    for (uint32_t i = 0; i < 3000; i++) step(&W);
    CHECK(W.coupons == 0, "dark then unlock within the Afterglow: no coupon");
}

static void s4_quorum_and_cap(void) {
    world_t W; world_init(&W); W.quorum = 0;
    for (uint32_t i = 0; i < Q + 3000; i++) step(&W);
    CHECK(W.coupons == 0 && W.w.ag_secs == 0, "no relay quorum: Afterglow never runs");
    ew_tick(&W.w, 86400, 1, W.sim.tip);
    CHECK(W.w.ag_secs == EW_TICK_CAP_SECS, "one report credits at most 30 min (%u)", W.w.ag_secs);
}

static void s5_forged_life(void) {
    /* last PIN at T; afterwards a lying ESP32 flags every signature as approved (tier 2)
     * and feeds notes signed by a stolen-nothing key... notes need the owner's key, so
     * model the worst case: notes every day (an RCE on a box with the scalar) */
    world_t W; world_init(&W); uint32_t T = W.sim.tip;
    for (uint32_t i = 0; i < 5 * Q && !W.coupons; i++) {
        ew_life(&W.w, EW_LIFE_TIER2, W.sim.tip, W.sim.tip);
        ew_life(&W.w, EW_LIFE_NOTE, W.sim.tip, W.sim.tip);
        step(&W);
    }
    CHECK(W.w.last_life <= T + Q, "forged tier-2/notes carry life at most one Quiet past the last PIN (%u > %u)", W.w.last_life, T + Q);
    CHECK(W.coupons >= 1 && W.first_coupon_height <= T + 3 * Q + 2, "forged life only delays: coupon at %u", W.first_coupon_height);
    printf("  forged tier-2 + notes daily after last PIN: life capped at +1 Quiet, coupon at +%.0f days\n", (W.first_coupon_height - T) / 144.0);
    /* Pulses are only built within one Quiet of the last PIN */
    CHECK(ew_pulse_allowed(&W.w, T + Q) && !ew_pulse_allowed(&W.w, T + Q + 1), "Pulse gate at last_tier1 + Quiet");
}

static void s6_away(void) {
    world_t W; world_init(&W);
    CHECK(ew_life(&W.w, EW_LIFE_AWAY, W.sim.tip + EW_AWAY_MAX + 1, W.sim.tip) == -1, "away beyond a year refused");
    CHECK(ew_life(&W.w, EW_LIFE_AWAY, W.sim.tip + 40000, W.sim.tip) == 1, "away 40000 blocks accepted");
    uint32_t A = W.sim.tip + 40000;
    for (uint32_t i = 0; i < 40000 + Q - 10; i++) step(&W);
    CHECK(W.coupons == 0, "no coupon while away + Quiet not reached");
    while (!W.coupons && W.sim.tip < A + 3 * Q) step(&W);
    CHECK(W.coupons && W.first_coupon_height >= A + Q + 1008, "away: silence counted from the away height (%u vs %u)", W.first_coupon_height, A + Q + 1008);
}

static void s7_reorg_undo(void) {
    world_t W; world_init(&W);
    while (W.w.link == 0) { if (W.sim.tip % 4320 == 0) ew_life(&W.w, EW_LIFE_TIER1, W.sim.tip, W.sim.tip); step(&W); }
    CHECK(W.w.adv_pending, "advance pending after 3 deep");
    W.sim.reorg_from = W.w.adv_height; W.sim.tag = 1;                  /* the refresh's block is replaced */
    ew_on_tip(&W.w, W.sim.tip, conf_fn, &W.sim);
    CHECK(W.w.link == 0 && !W.w.adv_pending, "reorg before 6 deep undoes the advance");
    uint8_t b[32]; bh(W.sim.tip - 2, 1, b);
    CHECK(ew_proof(&W.w, 'R', 1, b, 3, W.sim.tip - 2) == 1 && W.w.link == 1, "re-proof on the new branch advances again");
    for (int i = 0; i < 4; i++) { W.sim.tip++; ew_on_tip(&W.w, W.sim.tip, conf_fn, &W.sim); }
    CHECK(!W.w.adv_pending && W.w.link == 1, "settled at 6 deep");
    W.sim.tag = 2; ew_on_tip(&W.w, W.sim.tip, conf_fn, &W.sim);
    CHECK(W.w.link == 1, "a reorg after 6 deep is no longer watched");
    /* proofs that must be refused */
    world_init(&W); uint8_t z[32]; bh(TIP0, 0, z);
    CHECK(!ew_proof(&W.w, 'R', 2, z, 3, TIP0), "skipping a link refused");
    CHECK(!ew_proof(&W.w, 'R', 1, z, 2, TIP0), "2 deep refused");
    CHECK(!ew_proof(&W.w, 'C', 0, z, 1, TIP0), "coupon proof before kindling refused");
}

static void s8_rbf_and_late_refresh(void) {
    world_t W; world_init(&W);
    W.w.last_life = TIP0;                                               /* silent from the start */
    while (!W.coupons) step(&W);
    for (int i = 0; i < 120; i++) step(&W);
    CHECK(W.last_var == 2, "RBF: variants 1 and 2 followed every 36 blocks (last var %d)", W.last_var);
    CHECK(W.coupons == 3, "three variants released (%d)", W.coupons);
    /* a refresh released earlier confirms after kindling: coupon dead, walk moves on */
    world_init(&W);
    while (W.w.link == 0 && !W.pending_r_conf) { if (W.sim.tip % 4320 == 0) ew_life(&W.w, EW_LIFE_TIER1, W.sim.tip, W.sim.tip); step(&W); }
    W.pending_r_conf = 0; W.stuck = 1;                                  /* refresh released but stuck in mempool */
    W.w.ag_secs = EW_AFTERGLOW_SECS;
    while (!W.coupons && W.sim.tip < TIP0 + 4 * Q) step(&W);
    CHECK(W.coupons && W.w.kindled && W.w.link == 0, "kindled C0 while R1 unconfirmed");
    uint8_t b[32]; W.sim.tip += 3; bh(W.sim.tip - 2, 0, b);
    CHECK(ew_proof(&W.w, 'R', 1, b, 3, W.sim.tip - 2) && W.w.link == 1 && !W.w.kindled, "R1 confirming after kindle: link 1, un-kindled");
    ew_release_t r = ew_next(&W.w, W.sim.tip);
    CHECK(r.what == EW_NOTHING || (r.what == EW_COUPON && W.sim.tip >= ew_x(&W.w, 1)), "next coupon waits for X1");
}

int main(void) {
    printf("Emberwill chain walk, host tests\n");
    s1_alive();
    s2_dies(0, "dies at the ceremony");
    s2_dies(40 * 144, "dies on day 40");
    s2_dies(300 * 144, "dies on day 300");
    s2_dies(500 * 144, "dies on day 500");
    for (uint32_t d = 0; d < 400; d += 7) s2_dies_quiet(d * 144);
    printf("  deaths on every week of the first 400 days: worst payout last_life + %u blocks (%.2f Quiet)\n", worst, worst / (double)Q);
    s3_dark(); s4_quorum_and_cap(); s5_forged_life(); s6_away(); s7_reorg_undo(); s8_rbf_and_late_refresh();
    printf("%d passed, %d failed\n", pass, fail);
    return fail != 0;
}
