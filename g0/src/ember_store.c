/* ember_store.c — see ember_store.h. 28 Oct 2026. */
#include "ember_store.h"
#include "sha256.h"
#include <string.h>

/* Records are the in-RAM structs byte for byte (this firmware is the only
 * reader and writer; a G0 image is frozen for life), framed by a magic that
 * carries the struct size and a digest over everything before it. */
#define PLAN_MAGIC  "EMBRPLN2"
#define PLAN_BODY   sizeof(es_plan_t)
#define PLAN_LEN    ((8u + PLAN_BODY + 32u + 7u) & ~7u)
#define REC_MAGIC   "EMS2"
#define REC_BODY    sizeof(es_state_t)
#define REC_LEN     ((4u + 4u + 8u + REC_BODY + 16u + 7u) & ~7u)
#define REC_SLOTS   (ES_PAGE_SIZE / REC_LEN)
typedef char es_plan_fits[(PLAN_LEN <= ES_PAGE_SIZE) ? 1 : -1];
typedef char es_rec_fits[(REC_SLOTS >= 4) ? 1 : -1];

static int all_ff(const uint8_t *p, size_t n) { while (n--) if (*p++ != 0xFF) return 0; return 1; }

/* ── plan page ───────────────────────────────────────────────────────────── */
int es_plan_write(const es_flash_t *f, const es_plan_t *p) {
    static uint8_t buf[PLAN_LEN];
    memset(buf, 0, sizeof buf);
    memcpy(buf, PLAN_MAGIC, 8); memcpy(buf + 8, p, PLAN_BODY);
    sha256(buf, 8 + PLAN_BODY, buf + 8 + PLAN_BODY);
    int ok = !f->erase(f->ctx, ES_PLAN_ADDR) && !f->prog(f->ctx, ES_PLAN_ADDR, buf, PLAN_LEN) &&
             memcmp(f->map(f->ctx, ES_PLAN_ADDR), buf, PLAN_LEN) == 0;
    memset(buf, 0, sizeof buf);
    return ok ? 0 : -1;
}

int es_plan_load(const es_flash_t *f, es_plan_t *p) {
    const uint8_t *b = f->map(f->ctx, ES_PLAN_ADDR); uint8_t d[32];
    if (memcmp(b, PLAN_MAGIC, 8) != 0) return 0;
    sha256(b, 8 + PLAN_BODY, d);
    if (memcmp(d, b + 8 + PLAN_BODY, 32) != 0) return 0;
    memcpy(p, b + 8, PLAN_BODY);
    return 1;
}

int es_plan_erase(const es_flash_t *f) { return f->erase(f->ctx, ES_PLAN_ADDR); }

/* ── state log ───────────────────────────────────────────────────────────── */
static void rec_ser(const uint8_t plan_id[32], const es_state_t *s, uint8_t out[REC_LEN]) {
    uint32_t sz = (uint32_t)REC_BODY; uint8_t d[32];
    memset(out, 0, REC_LEN);
    memcpy(out, REC_MAGIC, 4); memcpy(out + 4, &sz, 4); memcpy(out + 8, plan_id, 8); memcpy(out + 16, s, REC_BODY);
    sha256(out, 16 + REC_BODY, d); memcpy(out + 16 + REC_BODY, d, 16);
}

static int rec_parse(const uint8_t *b, const uint8_t plan_id[32], es_state_t *s) {
    uint8_t d[32]; uint32_t sz = (uint32_t)REC_BODY;
    if (memcmp(b, REC_MAGIC, 4) != 0 || memcmp(b + 4, &sz, 4) != 0 || memcmp(b + 8, plan_id, 8) != 0) return 0;
    sha256(b, 16 + REC_BODY, d);
    if (memcmp(d, b + 16 + REC_BODY, 16) != 0) return 0;
    memcpy(s, b + 16, REC_BODY);
    return s->settled.ntimes >= 1 && s->settled.ntimes <= EH_MTP_SPAN;
}

/* newest valid record across both pages, which page holds it, and its first free slot */
typedef struct { int found; uint32_t seq; uint32_t page; int next_free; } scan_t;
static scan_t scan(const es_flash_t *f, const uint8_t plan_id[32], es_state_t *best) {
    static const uint32_t pages[2] = { ES_STATE_A_ADDR, ES_STATE_B_ADDR };
    scan_t sc = { 0, 0, ES_STATE_A_ADDR, -1 }; es_state_t s;
    for (int p = 0; p < 2; p++) {
        const uint8_t *base = f->map(f->ctx, pages[p]);
        for (uint32_t k = 0; k < REC_SLOTS; k++) {
            if (rec_parse(base + k * REC_LEN, plan_id, &s) && (!sc.found || s.seq > sc.seq)) {
                sc.found = 1; sc.seq = s.seq; sc.page = pages[p]; if (best) *best = s;
            }
        }
    }
    if (sc.found) {
        const uint8_t *base = f->map(f->ctx, sc.page);
        for (uint32_t k = 0; k < REC_SLOTS; k++) if (all_ff(base + k * REC_LEN, REC_LEN)) { sc.next_free = (int)k; break; }
    }
    return sc;
}

int es_state_load(const es_flash_t *f, const uint8_t plan_id[32], es_state_t *s) {
    return scan(f, plan_id, s).found;
}

int es_state_append(const es_flash_t *f, const uint8_t plan_id[32], es_state_t *s) {
    uint8_t rec[REC_LEN]; uint32_t addr;
    scan_t sc = scan(f, plan_id, NULL);
    s->seq = sc.found ? sc.seq + 1 : 1;
    rec_ser(plan_id, s, rec);
    if (sc.found && sc.next_free >= 0) {
        addr = sc.page + (uint32_t)sc.next_free * REC_LEN;
    } else {
        /* newest page full (or nothing yet): erase the other page and start it */
        addr = (sc.found && sc.page == ES_STATE_A_ADDR) ? ES_STATE_B_ADDR : ES_STATE_A_ADDR;
        if (f->erase(f->ctx, addr)) return -1;
    }
    if (f->prog(f->ctx, addr, rec, REC_LEN)) return -1;
    return memcmp(f->map(f->ctx, addr), rec, REC_LEN) == 0 ? 0 : -1;
}

int es_state_erase(const es_flash_t *f) {
    int a = f->erase(f->ctx, ES_STATE_A_ADDR), b = f->erase(f->ctx, ES_STATE_B_ADDR);
    return a || b;
}

void es_settle(const eh_chain_t *c, uint32_t depth, const eh_anchor_t *fallback, eh_anchor_t *out) {
    const eh_branch_t *m = &c->main;
    *out = *fallback;
    if (m->n < depth + EH_MTP_SPAN || m->tip < depth) return;
    uint32_t h = m->tip - depth;
    if (h <= fallback->height) return;
    const eh_ent_t *e = &m->r[h % EH_RING];
    out->height = h; memcpy(out->hash, e->hash, 32); out->bits = e->bits; out->pstart = e->pstart;
    out->ntimes = EH_MTP_SPAN;
    for (int i = 0; i < EH_MTP_SPAN; i++) out->times[i] = m->r[(h - (EH_MTP_SPAN - 1) + i) % EH_RING].time;
}
