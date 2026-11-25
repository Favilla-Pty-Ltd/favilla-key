/* ember_walk.c — see ember_walk.h. 28 Oct 2026. */
#include "ember_walk.h"
#include <string.h>

static uint32_t max32(uint32_t a, uint32_t b) { return a > b ? a : b; }
static uint32_t min32(uint32_t a, uint32_t b) { return a < b ? a : b; }

void ew_init(ew_state_t *w, uint32_t nlinks, uint32_t quiet, uint32_t x0, uint32_t tip) {
    memset(w, 0, sizeof(*w));
    w->nlinks = nlinks; w->quiet = quiet; w->x0 = x0;
    /* the ceremony is a spend-PIN session: tier-1 life at the ceremony tip */
    w->last_life = w->last_tier1 = w->last_pulse = tip; w->life_kind = EW_LIFE_TIER1;
}

uint32_t ew_x(const ew_state_t *w, uint32_t i) { return w->x0 + i * w->quiet; }

/* tip - last_life, 0 if last_life is at or above tip (an away date in the future) */
static uint32_t since_life(const ew_state_t *w, uint32_t tip) { return tip > w->last_life ? tip - w->last_life : 0; }

int ew_silent(const ew_state_t *w, uint32_t tip) { return since_life(w, tip) >= w->quiet; }

int ew_life(ew_state_t *w, int kind, uint32_t h, uint32_t tip) {
    uint32_t to;
    switch (kind) {
    case EW_LIFE_TIER1:
        h = min32(h, tip);                                  /* a PIN is now, never later */
        w->last_tier1 = max32(w->last_tier1, h); w->last_pulse = max32(w->last_pulse, h);
        to = h; break;
    case EW_LIFE_TIER2: to = min32(min32(h, tip), w->last_tier1 + w->quiet); break;
    case EW_LIFE_PULSE: h = min32(h, tip); w->last_pulse = max32(w->last_pulse, h); to = h; break;
    case EW_LIFE_NOTE:  to = min32(min32(h, tip), w->last_pulse + w->quiet); break;
    case EW_LIFE_AWAY:  if (h > tip + EW_AWAY_MAX) return -1; to = h; break;
    default: return -1;
    }
    if (w->kindled) return 0;                               /* bytes are out; life no longer changes the plan */
    if (to <= w->last_life) return 0;
    w->last_life = to; w->life_kind = (uint8_t)kind;
    w->ag_secs = 0;                                         /* any life cancels the Afterglow */
    return 1;
}

void ew_tick(ew_state_t *w, uint32_t secs, int quorum, uint32_t tip) {
    if (!quorum || w->kindled || !ew_silent(w, tip)) return;
    secs = min32(secs, EW_TICK_CAP_SECS);
    w->ag_secs = (w->ag_secs > 0xFFFFFFFFu - secs) ? 0xFFFFFFFFu : w->ag_secs + secs;
}

int ew_pulse_allowed(const ew_state_t *w, uint32_t tip) { return tip <= w->last_tier1 + w->quiet; }

int ew_afterglow_served(const ew_state_t *w, uint32_t tip) {
    return ew_silent(w, tip) && w->ag_secs >= EW_AFTERGLOW_SECS &&
           tip >= w->last_life + w->quiet + EW_AFTERGLOW_BLOCKS;
}

void ew_on_tip(ew_state_t *w, uint32_t tip, ew_conf_fn conf, void *ctx) {
    (void)tip;
    if (w->adv_pending) {
        uint32_t c = conf(ctx, w->adv_block);
        if (c == 0) { w->link--; w->adv_pending = 0; }     /* the refresh's block left the main branch */
        else if (c >= EW_FINAL_DEPTH) w->adv_pending = 0;
    }
    if (w->done_pending) {
        uint32_t c = conf(ctx, w->done_block);
        if (c == 0) w->done_pending = 0;                    /* kindling reorged out: keep releasing */
        else if (c >= EW_FINAL_DEPTH) { w->done_pending = 0; w->done = 1; }
    }
}

int ew_proof(ew_state_t *w, char which, uint32_t idx, const uint8_t block[32], uint32_t conf, uint32_t bh) {
    if (w->done) return 0;
    if (which == 'R') {
        /* the next refresh, 3 deep, while no advance is pending. A refresh released
         * before the owner fell silent can still confirm after the coupon was
         * kindled: the two spend the same output, so the coupon is now dead and
         * the walk moves to the next link, which kindles at its own X. */
        if (w->adv_pending || w->done_pending || idx != w->link + 1 || idx > w->nlinks || conf < EW_ADV_DEPTH) return 0;
        w->link = idx; w->adv_pending = 1; w->adv_height = bh; memcpy(w->adv_block, block, 32);
        w->kindled = 0; w->kvar = 0; w->kheight = 0;
        return 1;
    }
    if (which == 'C') {
        if (!w->kindled || idx != w->link || w->done_pending || conf < 1) return 0;
        w->done_pending = 1; w->done_height = bh; memcpy(w->done_block, block, 32);
        return 1;
    }
    return 0;
}

ew_release_t ew_next(const ew_state_t *w, uint32_t tip) {
    ew_release_t r = { EW_NOTHING, 0, 0 };
    if (w->done || w->done_pending) return r;
    if (w->kindled) {
        r.what = EW_COUPON; r.link = w->link; r.var = w->kvar;
        if (tip >= w->kheight + EW_RBF_BLOCKS && (uint32_t)w->kvar + 1 < EW_CVARS) r.var = w->kvar + 1;
        return r;
    }
    if (ew_afterglow_served(w, tip) && tip >= ew_x(w, w->link) && !w->adv_pending) {
        r.what = EW_COUPON; r.link = w->link; r.var = 0; return r;
    }
    /* refresh window: owner alive within half a Quiet, at or past the refresh's own locktime */
    if (!w->adv_pending && w->link < w->nlinks && since_life(w, tip) < w->quiet / 2 &&
        tip >= ew_x(w, w->link) - w->quiet / 2) {
        r.what = EW_REFRESH; r.link = w->link + 1; return r;
    }
    return r;
}

void ew_released(ew_state_t *w, ew_release_t r, uint32_t tip) {
    if (r.what != EW_COUPON) return;
    if (!w->kindled) { w->kindled = 1; w->kvar = 0; w->kheight = tip; return; }
    if (r.var > w->kvar) { w->kvar = (uint8_t)r.var; w->kheight = tip; }
}
