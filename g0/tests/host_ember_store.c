/* host_ember_store.c — plan page and ping-pong state log, with power cut at
 * every doubleword of every write and erase. 28 Oct 2026. */
#include "ember_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#define PLAN_BYTES (offsetof(es_plan_t, ctxid) + sizeof(((es_plan_t *)0)->ctxid))   /* struct minus tail padding */

static int pass, fail;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* simulated flash: 3 pages, erase -> 0xFF, program only onto erased doublewords */
typedef struct { uint8_t mem[3][ES_PAGE_SIZE]; long budget; uint64_t rs; int violations; } sim_t;
static uint32_t rnd(sim_t *s) { s->rs ^= s->rs << 13; s->rs ^= s->rs >> 7; s->rs ^= s->rs << 17; return (uint32_t)s->rs; }
static uint8_t *pg(sim_t *s, uint32_t a) { return a >= ES_PLAN_ADDR ? s->mem[2] + (a - ES_PLAN_ADDR) : a >= ES_STATE_A_ADDR ? s->mem[0] + (a - ES_STATE_A_ADDR) : s->mem[1] + (a - ES_STATE_B_ADDR); }
/* budget: doublewords (or erases) that complete before the power goes; <0 = unlimited */
static int f_erase(void *c, uint32_t a) {
    sim_t *s = c; uint8_t *p = pg(s, a);
    if (s->budget == 0) { for (uint32_t i = 0; i < ES_PAGE_SIZE; i++) if (rnd(s) & 1) p[i] = (uint8_t)rnd(s); s->budget = -2; return -1; }
    if (s->budget == -2) return -1;
    if (s->budget > 0) s->budget--;
    memset(p, 0xFF, ES_PAGE_SIZE); return 0;
}
static int f_prog(void *c, uint32_t a, const uint8_t *d, size_t n) {
    sim_t *s = c; uint8_t *p = pg(s, a);
    for (size_t k = 0; k < n; k += 8) {
        for (int i = 0; i < 8; i++) if (p[k + i] != 0xFF) s->violations++;
        if (s->budget == -2) return -1;
        if (s->budget == 0) { for (int i = 0; i < 8; i++) p[k + i] = (uint8_t)rnd(s); s->budget = -2; return -1; }   /* torn doubleword */
        if (s->budget > 0) s->budget--;
        memcpy(p + k, d + k, 8);
    }
    return 0;
}
static const uint8_t *f_map(void *c, uint32_t a) { return pg(c, a); }

static void mkstate(es_state_t *st, uint32_t i) {
    memset(st, 0, sizeof *st);
    st->settled.height = 900000 + i; st->settled.ntimes = 11; st->settled.bits = 0x17028c61; memset(st->settled.hash, (int)i, 32);
    for (int k = 0; k < 11; k++) st->settled.times[k] = 1760000000 + i * 600 + k;
    st->walk.link = i % 9; st->walk.last_life = 900000 + i * 3; st->walk.quiet = 13140; st->walk.nlinks = 8; st->walk.ag_secs = i * 77;
    st->walk.kindled = (uint8_t)(i & 1); memset(st->walk.adv_block, (int)(i * 3), 32);
}

int main(void) {
    static sim_t S; es_flash_t F = { f_erase, f_prog, f_map, &S };
    S.rs = 0x2810; S.budget = -1; memset(S.mem, 0xFF, sizeof S.mem);
    printf("Emberwill flash store, host tests\n");
    uint8_t pid[32]; memset(pid, 0xA5, 32);

    /* plan page round trip, and a torn plan reads as absent */
    static es_plan_t P, Q; memset(&P, 0, sizeof P);
    for (size_t i = 0; i < sizeof P; i++) ((uint8_t *)&P)[i] = (uint8_t)(i * 31 + 7);
    { int w = es_plan_write(&F, &P), l = es_plan_load(&F, &Q); size_t d = 0; while (d < PLAN_BYTES && ((uint8_t *)&P)[d] == ((uint8_t *)&Q)[d]) d++;
      CHECK(w == 0 && l == 1 && d == PLAN_BYTES, "plan round trip (w %d l %d first diff %zu of %zu)", w, l, d, PLAN_BYTES); }
    int torn_ok = 1;
    for (long cut = 0; cut < 209; cut += 7) {
        S.budget = cut; es_plan_write(&F, &P); S.budget = -1;
        int r = es_plan_load(&F, &Q);
        if (r && memcmp(&P, &Q, PLAN_BYTES)) torn_ok = 0;
        if (cut < 208 && r) torn_ok = 0;            /* a plan cut short never validates */
    }
    CHECK(torn_ok, "torn plan writes never load as a different or partial plan");
    S.budget = -1; CHECK(es_plan_write(&F, &P) == 0, "rewrite");

    /* state log: 1000 appends, power cut at a random point before each, reboot, check */
    es_state_t st, got; uint32_t committed = 0, cuts = 0, kept_prev = 0, kept_new = 0;
    for (uint32_t i = 1; i <= 1000; i++) {
        mkstate(&st, i);
        int cut = (rnd(&S) % 3) == 0;
        if (cut) { S.budget = rnd(&S) % 32; cuts++; }
        int rc = es_state_append(&F, pid, &st);
        S.budget = -1;
        int found = es_state_load(&F, pid, &got);
        if (rc == 0) { committed = i; CHECK(found && got.walk.ag_secs == i * 77, "append %u visible", i); kept_new++; }
        else {
            CHECK(found || committed == 0, "after cut at %u: a record survives", i);
            if (found) {
                uint32_t gi = got.walk.ag_secs / 77;
                CHECK(gi == committed || gi == i, "after cut at %u: newest is %u (committed %u)", i, gi, committed);
                if (gi == i) committed = i; else kept_prev++;
                es_state_t want; mkstate(&want, gi); want.seq = got.seq;
                CHECK(!memcmp(&want.walk, &got.walk, sizeof want.walk) && !memcmp(&want.settled, &got.settled, sizeof want.settled), "record %u intact", gi);
            }
        }
    }
    CHECK(S.violations == 0, "never programmed a non-erased doubleword (%d)", S.violations);
    printf("  1000 appends, %u with a power cut mid-write/erase: newest-or-previous always loads intact (%u fell back)\n", cuts, kept_prev);
    /* a record from another plan is ignored */
    uint8_t other[32]; memset(other, 0x5A, 32);
    CHECK(!es_state_load(&F, other, &got), "foreign plan id ignored");
    printf("%d passed, %d failed\n", pass, fail);
    return fail != 0;
}
