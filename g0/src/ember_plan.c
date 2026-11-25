/* ember_plan.c — see ember_plan.h. 28 Oct 2026. */
#include "ember_plan.h"
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
static int allzero(const uint8_t *p, size_t n) { uint8_t o = 0; while (n--) o |= *p++; return o == 0; }

/* Wire layout (little-endian):
 *   0   ncoins, nheirs, nlinks, reserved(0)
 *   4   coin[3]  { txid 32 | vout 4 | amount 8 | change 4 | index 4 }   52 each
 *   160 heir[6]  { spk slot 34 | basis points 2 }                         36 each
 *   376 executor spk slot 34
 *   410 quiet 4 | 414 ref_index 4 | 418 crate[3] 2 each | 424 rrate 2 | 426 bump 4
 *   430 end
 * Unused coin and heir slots must be all zero. */
int ep_set_parse(const uint8_t *b, size_t len, ep_set_t *s) {
    if (len != EP_SET_LEN) return EP_E_LEN;
    memset(s, 0, sizeof(*s));
    s->ncoins = b[0]; s->nheirs = b[1]; s->nlinks = b[2];
    if (b[3] != 0) return EP_E_PAD;
    if (s->ncoins < 1 || s->ncoins > EP_MAX_COINS || s->nheirs < 1 || s->nheirs > EP_MAX_HEIRS ||
        s->nlinks < 1 || s->nlinks > EP_MAX_LINKS) return EP_E_COUNT;
    for (int i = 0; i < EP_MAX_COINS; i++) {
        const uint8_t *c = b + 4 + 52 * i;
        if (i >= s->ncoins) { if (!allzero(c, 52)) return EP_E_PAD; continue; }
        memcpy(s->coin[i].txid, c, 32); s->coin[i].vout = rd32(c + 32); s->coin[i].amount = rd64(c + 36);
        s->coin[i].change = rd32(c + 44); s->coin[i].index = rd32(c + 48);
    }
    for (int i = 0; i < EP_MAX_HEIRS; i++) {
        const uint8_t *h = b + 160 + 36 * i;
        if (i >= s->nheirs) { if (!allzero(h, 36)) return EP_E_PAD; continue; }
        memcpy(s->heir[i].spk, h, 34); s->heir[i].bp = rd16(h + 34);
    }
    memcpy(s->exec_spk, b + 376, 34);
    s->quiet = rd32(b + 410); s->ref_index = rd32(b + 414);
    for (int i = 0; i < EP_CVARS; i++) s->crate[i] = rd16(b + 418 + 2 * i);
    s->rrate = rd16(b + 424); s->bump = rd32(b + 426);
    return EP_OK;
}

uint32_t ep_count(const ep_set_t *s) { return EP_CVARS + (uint32_t)s->nlinks * (1 + EP_CVARS); }
ep_id_t ep_id_at(uint32_t k) {
    ep_id_t id;
    if (k < EP_CVARS) { id.kind = 'C'; id.link = 0; id.var = (uint8_t)k; return id; }
    k -= EP_CVARS;
    id.link = (uint8_t)(k / (1 + EP_CVARS) + 1);
    uint32_t r = k % (1 + EP_CVARS);
    if (r == 0) { id.kind = 'R'; id.var = 0; } else { id.kind = 'C'; id.var = (uint8_t)(r - 1); }
    return id;
}

uint32_t ep_x(const ep_set_t *s, uint32_t tip, uint32_t i) { return tip + s->quiet + EP_AFTERGLOW + i * s->quiet; }

/* floor(a * bp / 10000) without 64-bit overflow (a <= 2.1e15) */
static uint64_t share(uint64_t a, uint16_t bp) { return (a / 10000u) * bp + ((a % 10000u) * bp) / 10000u; }

static void set_coins(const ep_set_t *s, const uint8_t pub[EP_MAX_COINS][33], et_tx_t *tx) {
    tx->nin = s->ncoins;
    for (int i = 0; i < s->ncoins; i++) {
        memcpy(tx->in[i].txid, s->coin[i].txid, 32); tx->in[i].vout = s->coin[i].vout;
        tx->in[i].amount = s->coin[i].amount; tx->in[i].seq = ET_SEQ_RBF; memcpy(tx->in[i].pub, pub[i], 33);
    }
}
static int fee_of(et_tx_t *tx, uint16_t rate, uint64_t *fee) { *fee = (uint64_t)rate * et_vsize_max(tx); return 0; }
static uint64_t in_sum(const et_tx_t *tx) { uint64_t a = 0; for (int i = 0; i < tx->nin; i++) a += tx->in[i].amount; return a; }

/* Refresh R_k (k >= 1). Builds R_1..R_k in turn: each spends the previous one's output. */
static int build_r(const ep_set_t *s, uint32_t tip, const uint8_t cpub[EP_MAX_COINS][33],
                   const uint8_t rpub[EP_MAX_LINKS][33], uint32_t k, et_tx_t *tx) {
    uint8_t prev[32]; uint64_t prev_amt = 0;
    for (uint32_t j = 1; j <= k; j++) {
        memset(tx, 0, sizeof(*tx)); tx->version = 2;
        if (j == 1) set_coins(s, cpub, tx);
        else { tx->nin = 1; memcpy(tx->in[0].txid, prev, 32); tx->in[0].vout = 0; tx->in[0].amount = prev_amt;
               tx->in[0].seq = ET_SEQ_RBF; memcpy(tx->in[0].pub, rpub[j - 2], 33); }
        tx->nout = 1; tx->out[0].spklen = 22; et_p2wpkh_spk(rpub[j - 1], tx->out[0].spk);
        tx->locktime = ep_x(s, tip, j - 1) - s->quiet / 2;
        uint64_t fee, in = in_sum(tx); fee_of(tx, s->rrate, &fee);
        if (fee + EP_DUST > in) return EP_E_DUST;
        tx->out[0].amount = in - fee;
        et_txid(tx, prev); prev_amt = tx->out[0].amount;
    }
    return EP_OK;
}

int ep_build(const ep_set_t *s, uint32_t tip, const uint8_t cpub[EP_MAX_COINS][33],
             const uint8_t rpub[EP_MAX_LINKS][33], ep_id_t id, et_tx_t *tx) {
    if (id.kind == 'R') {
        if (id.link < 1 || id.link > s->nlinks || id.var) return EP_E_COUNT;
        return build_r(s, tip, cpub, rpub, id.link, tx);
    }
    if (id.kind != 'C' || id.link > s->nlinks || id.var >= EP_CVARS) return EP_E_COUNT;
    uint8_t ptx[32]; uint64_t pamt = 0;
    if (id.link > 0) {
        int rc = build_r(s, tip, cpub, rpub, id.link, tx); if (rc) return rc;
        et_txid(tx, ptx); pamt = tx->out[0].amount;
    }
    memset(tx, 0, sizeof(*tx)); tx->version = 2;
    if (id.link == 0) set_coins(s, cpub, tx);
    else { tx->nin = 1; memcpy(tx->in[0].txid, ptx, 32); tx->in[0].vout = 0; tx->in[0].amount = pamt;
           tx->in[0].seq = ET_SEQ_RBF; memcpy(tx->in[0].pub, rpub[id.link - 1], 33); }
    tx->nout = (uint8_t)(s->nheirs + 1);
    for (int h = 0; h < s->nheirs; h++) { tx->out[h].spklen = et_spk_len(s->heir[h].spk); memcpy(tx->out[h].spk, s->heir[h].spk, 34); }
    et_out_t *b = &tx->out[s->nheirs]; b->spklen = et_spk_len(s->exec_spk); memcpy(b->spk, s->exec_spk, 34); b->amount = s->bump;
    tx->locktime = ep_x(s, tip, id.link);
    uint64_t fee, in = in_sum(tx); fee_of(tx, s->crate[id.var], &fee);
    if (fee + s->bump > in) return EP_E_DUST;
    uint64_t avail = in - fee - s->bump, given = 0;
    for (int h = 0; h < s->nheirs; h++) { tx->out[h].amount = share(avail, s->heir[h].bp); given += tx->out[h].amount; }
    tx->out[0].amount += avail - given;                                  /* rounding dust to heir 1 */
    for (int h = 0; h < s->nheirs; h++) if (tx->out[h].amount < EP_DUST) return EP_E_DUST;
    return EP_OK;
}

int ep_validate(const ep_set_t *s, uint32_t tip) {
    if (s->ncoins < 1 || s->ncoins > EP_MAX_COINS || s->nheirs < 1 || s->nheirs > EP_MAX_HEIRS ||
        s->nlinks < 1 || s->nlinks > EP_MAX_LINKS) return EP_E_COUNT;
    uint64_t total = 0;
    for (int i = 0; i < s->ncoins; i++) {
        if (s->coin[i].amount < EP_DUST || s->coin[i].amount > EP_MAX_SATS) return EP_E_AMOUNT;
        total += s->coin[i].amount;
        if (s->coin[i].change > 1 || (s->coin[i].index & 0x80000000u)) return EP_E_DERIV;
        for (int j = 0; j < i; j++)
            if (!memcmp(s->coin[i].txid, s->coin[j].txid, 32) && s->coin[i].vout == s->coin[j].vout) return EP_E_DUPCOIN;
    }
    if (total > EP_MAX_SATS) return EP_E_AMOUNT;
    uint32_t bp = 0;
    for (int h = 0; h < s->nheirs; h++) {
        if (!et_spk_len(s->heir[h].spk)) return EP_E_SPK;
        if (s->heir[h].bp == 0) return EP_E_BP;
        bp += s->heir[h].bp;
    }
    if (bp != 10000u) return EP_E_BP;
    if (!et_spk_len(s->exec_spk)) return EP_E_SPK;
    if (s->quiet < EP_QUIET_MIN || s->quiet > EP_QUIET_MAX) return EP_E_QUIET;
    if (s->ref_index >= 0x80000000u - EP_MAX_LINKS) return EP_E_DERIV;
    for (int v = 0; v < EP_CVARS; v++) {
        if (s->crate[v] < 1 || s->crate[v] > EP_RATE_MAX) return EP_E_RATE;
        if (v && s->crate[v] <= s->crate[v - 1]) return EP_E_RATE;
    }
    if (s->rrate < 1 || s->rrate > EP_RATE_MAX) return EP_E_RATE;
    if (s->bump < EP_DUST || s->bump > 1000000u) return EP_E_AMOUNT;
    if ((uint64_t)ep_x(s, tip, s->nlinks) >= 500000000u) return EP_E_QUIET;     /* must stay a height locktime */
    /* every transaction of the plan must build, outputs at or above dust */
    /* sizes and amounts do not depend on the keys: any well-formed placeholder will do */
    uint8_t z[EP_MAX_LINKS][33]; et_tx_t tx;
    memset(z, 2, sizeof z);
    for (uint32_t k = 0; k < ep_count(s); k++) {
        int rc = ep_build(s, tip, (const uint8_t (*)[33])z, (const uint8_t (*)[33])z, ep_id_at(k), &tx);
        if (rc) return rc;
    }
    return EP_OK;
}
