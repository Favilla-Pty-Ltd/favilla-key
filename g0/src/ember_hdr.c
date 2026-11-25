/* ember_hdr.c — see ember_hdr.h. 28 Oct 2026. */
#include "ember_hdr.h"
#include "sha256.h"
#include <string.h>

/* Mainnet. pow limit 0x00000000ffff...ff (2^224 - 1). */
const eh_params_t EH_MAINNET = {
    .pow_limit = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                   0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u },
    .interval = 2016, .timespan = 14u * 24u * 60u * 60u, .no_retarget = 0,
    .v2_height = 227931, .v3_height = 363725, .v4_height = 388381,
};

/* ── 256-bit arithmetic on little-endian 32-bit limbs ───────────────────── */
static int u256_cmp(const uint32_t a[8], const uint32_t b[8]) {
    for (int i = 7; i >= 0; i--) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static int u256_zero(const uint32_t a[8]) {
    uint32_t o = 0; for (int i = 0; i < 8; i++) o |= a[i]; return o == 0;
}
static void u256_add(uint32_t r[8], const uint32_t a[8]) {
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (uint64_t)r[i] + a[i]; r[i] = (uint32_t)c; c >>= 32; }
}
static void u256_sub(uint32_t r[8], const uint32_t a[8]) {
    int64_t b = 0;
    for (int i = 0; i < 8; i++) { int64_t d = (int64_t)r[i] - a[i] + b; r[i] = (uint32_t)d; b = d < 0 ? -1 : 0; }
}
static void u256_shl1(uint32_t r[8]) {
    for (int i = 7; i > 0; i--) r[i] = (r[i] << 1) | (r[i - 1] >> 31);
    r[0] <<= 1;
}
/* q = n / d (d != 0), shift-subtract. Only used for work, a handful per reorg. */
static void u256_div(const uint32_t n[8], const uint32_t d[8], uint32_t q[8]) {
    uint32_t rem[8] = {0};
    memset(q, 0, 32);
    for (int bit = 255; bit >= 0; bit--) {
        u256_shl1(rem);
        rem[0] |= (n[bit >> 5] >> (bit & 31)) & 1u;
        if (u256_cmp(rem, d) >= 0) { u256_sub(rem, d); q[bit >> 5] |= 1u << (bit & 31); }
    }
}
static uint8_t u256_byte(const uint32_t t[8], int k) {
    return (k < 0 || k > 31) ? 0 : (uint8_t)(t[k >> 2] >> (8 * (k & 3)));
}
static void u256_from_le(const uint8_t b[32], uint32_t t[8]) {
    for (int i = 0; i < 8; i++)
        t[i] = (uint32_t)b[4*i] | ((uint32_t)b[4*i+1] << 8) | ((uint32_t)b[4*i+2] << 16) | ((uint32_t)b[4*i+3] << 24);
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ── consensus arithmetic, byte-exact with Core's arith_uint256 ─────────── */
/* SetCompact without the flags; returns 1 only if the result is a usable
 * target (not negative, not overflowing, not zero). */
static void compact_raw(uint32_t bits, uint32_t t[8]) {
    uint32_t size = bits >> 24, word = bits & 0x007FFFFFu;
    memset(t, 0, 32);
    if (size <= 3) { t[0] = word >> (8 * (3 - size)); return; }
    for (int i = 0; i < 3; i++) {
        int k = (int)size - 3 + i;
        if (k < 32) t[k >> 2] |= ((word >> (8 * i)) & 0xFFu) << (8 * (k & 3));
    }
}
int eh_bits_to_target(uint32_t bits, uint32_t t[8]) {
    uint32_t size = bits >> 24, word = bits & 0x007FFFFFu;
    if (size <= 3) word >>= 8 * (3 - size);
    if (word != 0 && (bits & 0x00800000u)) return 0;                              /* negative */
    if (word != 0 && (size > 34 || (word > 0xFF && size > 33) || (word > 0xFFFF && size > 32))) return 0; /* overflow */
    compact_raw(bits, t);
    return !u256_zero(t);
}
uint32_t eh_target_to_bits(const uint32_t t[8]) {
    int size = 32;
    while (size > 0 && u256_byte(t, size - 1) == 0) size--;
    uint32_t c = ((uint32_t)u256_byte(t, size - 1) << 16) | ((uint32_t)u256_byte(t, size - 2) << 8) | u256_byte(t, size - 3);
    if (c & 0x00800000u) { c >>= 8; size++; }
    return c | ((uint32_t)size << 24);
}
uint32_t eh_retarget(const eh_params_t *p, uint32_t last_bits, uint32_t first_time, uint32_t last_time) {
    int64_t span = (int64_t)last_time - (int64_t)first_time;
    if (span < (int64_t)(p->timespan / 4)) span = p->timespan / 4;
    if (span > (int64_t)p->timespan * 4)   span = (int64_t)p->timespan * 4;
    uint32_t t[8]; compact_raw(last_bits, t);
    /* t *= span, then t /= timespan. Core's arith_uint256 would wrap on overflow;
     * params keep pow_limit * 4 * timespan < 2^256 so it never does. */
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (uint64_t)t[i] * (uint32_t)span; t[i] = (uint32_t)c; c >>= 32; }
    if (c) return eh_target_to_bits(p->pow_limit);   /* cannot happen for mainnet (2^224 * 4838400 < 2^247) */
    uint64_t rem = 0;
    for (int i = 7; i >= 0; i--) { uint64_t cur = (rem << 32) | t[i]; t[i] = (uint32_t)(cur / p->timespan); rem = cur % p->timespan; }
    if (u256_cmp(t, p->pow_limit) > 0) memcpy(t, p->pow_limit, 32);
    return eh_target_to_bits(t);
}
void eh_work(uint32_t bits, uint32_t w[8]) {
    uint32_t t[8], nt[8], one[8] = {1};
    if (!eh_bits_to_target(bits, t)) { memset(w, 0, 32); return; }
    for (int i = 0; i < 8; i++) nt[i] = ~t[i];
    u256_add(t, one);                       /* t + 1 (t <= pow limit, cannot wrap) */
    u256_div(nt, t, w);                     /* ~t / (t+1) */
    u256_add(w, one);                       /* + 1  ==  2^256 / (t+1) */
}

void eh_hash(const uint8_t hdr[80], uint8_t out[32]) {
    uint8_t h1[32];
    sha256(hdr, 80, h1);
    sha256(h1, 32, out);
}

/* ── branches ───────────────────────────────────────────────────────────── */
static int has(const eh_branch_t *b, uint32_t h) { return h <= b->tip && b->tip - h < b->n; }
static eh_ent_t *ent(eh_branch_t *b, uint32_t h) { return &b->r[h % EH_RING]; }
static const eh_ent_t *cent(const eh_branch_t *b, uint32_t h) { return &b->r[h % EH_RING]; }
static int zero32(const uint8_t *p) { uint8_t o = 0; for (int i = 0; i < 32; i++) o |= p[i]; return o == 0; }

void eh_init(eh_chain_t *c, const eh_params_t *p, const eh_anchor_t *a) {
    memset(c, 0, sizeof(*c));
    c->p = p;
    c->floor_height = a->height;
    uint32_t nt = a->ntimes ? a->ntimes : 1;
    if (nt > EH_MTP_SPAN) nt = EH_MTP_SPAN;
    if (nt > a->height + 1) nt = a->height + 1;
    c->main.tip = a->height; c->main.n = nt;
    for (uint32_t i = 0; i < nt; i++) {
        eh_ent_t *e = ent(&c->main, a->height - (nt - 1) + i);
        e->time = a->times[(a->ntimes ? a->ntimes : 1) - nt + i];
        e->bits = a->bits; e->pstart = a->pstart;
    }
    memcpy(ent(&c->main, a->height)->hash, a->hash, 32);
    c->base = a->height - (nt - 1);
    c->last_fork = a->height;
}

static uint32_t mtp_of(const eh_branch_t *b, uint32_t ph, uint32_t *count) {
    uint32_t v[EH_MTP_SPAN], k = 0;
    for (uint32_t i = 0; i < EH_MTP_SPAN && i <= ph && has(b, ph - i); i++) {
        uint32_t x = cent(b, ph - i)->time, j = k++;
        while (j > 0 && v[j - 1] > x) { v[j] = v[j - 1]; j--; }
        v[j] = x;
    }
    *count = k;
    return k ? v[k / 2] : 0;
}

/* Every rule that does not depend on which branch wins. src holds the parent
 * at height ph and its ancestors. */
static int check(const eh_chain_t *c, const eh_branch_t *src, uint32_t ph,
                 const uint8_t hdr[80], const uint8_t hash[32], uint32_t *pstart_out) {
    const eh_params_t *p = c->p;
    const eh_ent_t *par = cent(src, ph);
    uint32_t h = ph + 1, time = rd32(hdr + 68), bits = rd32(hdr + 72);

    /* proof of work (CheckProofOfWork) */
    uint32_t t[8], hv[8];
    if (!eh_bits_to_target(bits, t) || u256_cmp(t, p->pow_limit) > 0) return EH_E_POW;
    u256_from_le(hash, hv);
    if (u256_cmp(hv, t) > 0) return EH_E_POW;

    /* difficulty (GetNextWorkRequired, mainnet: no min-difficulty rule) */
    uint32_t want = par->bits;
    if (!p->no_retarget && h % p->interval == 0) want = eh_retarget(p, par->bits, par->pstart, par->time);
    if (bits != want) return EH_E_BITS;

    /* median time past */
    uint32_t cnt, mtp = mtp_of(src, ph, &cnt);
    if (cnt < EH_MTP_SPAN && ph + 1 - cnt != c->base) return EH_E_DEEP;   /* history cut off by the ring */
    if (time <= mtp) return EH_E_TIME;

    /* outdated versions (BIP34/66/65) */
    int32_t ver = (int32_t)rd32(hdr);    /* signed, as in Core */
    if ((h >= p->v2_height && ver < 2) || (h >= p->v3_height && ver < 3) || (h >= p->v4_height && ver < 4)) return EH_E_VER;

    *pstart_out = (h % p->interval == 0) ? time : par->pstart;
    return 0;
}

static void append(eh_branch_t *b, const uint8_t hash[32], const uint8_t hdr[80], uint32_t pstart) {
    b->tip++;
    eh_ent_t *e = ent(b, b->tip);
    memcpy(e->hash, hash, 32);
    e->time = rd32(hdr + 68); e->bits = rd32(hdr + 72); e->pstart = pstart;
    if (b->n < EH_RING) b->n++;
}

static void work_since(const eh_branch_t *b, uint32_t fork, uint32_t sum[8]) {
    memset(sum, 0, 32);
    for (uint32_t h = fork + 1; h <= b->tip; h++) { uint32_t w[8]; eh_work(cent(b, h)->bits, w); u256_add(sum, w); }
}

static int find_in(const eh_branch_t *b, const uint8_t hash[32], uint32_t lo, uint32_t *height) {
    for (uint32_t i = 0; i < b->n; i++) {
        uint32_t h = b->tip - i;
        if (h < lo) break;
        if (memcmp(cent(b, h)->hash, hash, 32) == 0 && !zero32(hash)) { *height = h; return 1; }
    }
    return 0;
}

int eh_connect(eh_chain_t *c, const uint8_t hdr[80]) {
    uint8_t hash[32]; uint32_t ph, pstart; int rc;
    const uint8_t *prev = hdr + 4;
    eh_hash(hdr, hash);

    if (find_in(&c->main, hash, 0, &ph)) return EH_DUP;
    if (c->cand.live && find_in(&c->cand, hash, c->cand.fork + 1, &ph)) return EH_DUP;

    /* 1. extends the main tip */
    if (memcmp(prev, cent(&c->main, c->main.tip)->hash, 32) == 0) {
        if ((rc = check(c, &c->main, c->main.tip, hdr, hash, &pstart))) return rc;
        append(&c->main, hash, hdr, pstart);
        if (c->cand.live && c->main.tip - c->cand.fork >= EH_RING) c->cand.live = 0;  /* hopeless and unverifiable */
        return EH_TIP;
    }

    /* 2. extends the candidate tip, or 3. forks from a recent main block */
    if (c->cand.live && memcmp(prev, cent(&c->cand, c->cand.tip)->hash, 32) == 0) {
        if ((rc = check(c, &c->cand, c->cand.tip, hdr, hash, &pstart))) return rc;
        append(&c->cand, hash, hdr, pstart);
    } else {
        if (!find_in(&c->main, prev, c->floor_height, &ph) || ph == c->main.tip) return EH_E_ORPHAN;
        if ((rc = check(c, &c->main, ph, hdr, hash, &pstart))) return rc;
        c->cand = c->main;                                  /* share history up to the fork */
        c->cand.n -= c->main.tip - ph;
        c->cand.tip = ph; c->cand.fork = ph; c->cand.live = 1;
        append(&c->cand, hash, hdr, pstart);
    }

    /* most work since the fork wins; ties keep the main branch */
    uint32_t wm[8], wc[8];
    work_since(&c->main, c->cand.fork, wm);
    work_since(&c->cand, c->cand.fork, wc);
    if (u256_cmp(wc, wm) > 0) {
        c->last_fork = c->cand.fork;
        c->main = c->cand;
        c->main.live = 0; c->main.fork = 0;
        c->cand.live = 0;
        return EH_REORG;
    }
    return EH_SIDE;
}

uint32_t eh_last_fork(const eh_chain_t *c) { return c->last_fork; }
const eh_ent_t *eh_tip(const eh_chain_t *c) { return cent(&c->main, c->main.tip); }
uint32_t eh_tip_height(const eh_chain_t *c) { return c->main.tip; }
uint32_t eh_tip_mtp(const eh_chain_t *c) { uint32_t n; return mtp_of(&c->main, c->main.tip, &n); }

uint32_t eh_find_main(const eh_chain_t *c, const uint8_t hash[32], uint32_t *height) {
    uint32_t h;
    if (!find_in(&c->main, hash, 0, &h)) return 0;
    if (height) *height = h;
    return c->main.tip - h + 1;
}

/* ── Merkle ─────────────────────────────────────────────────────────────── */
int eh_merkle_check(const uint8_t txid[32], uint32_t index, uint8_t depth,
                    const uint8_t branch[][32], const uint8_t root[32]) {
    uint8_t cur[32], buf[64];
    if (depth > EH_MERKLE_MAX_DEPTH || (index >> depth) != 0) return 0;
    memcpy(cur, txid, 32);
    for (uint8_t i = 0; i < depth; i++) {
        if ((index >> i) & 1u) { memcpy(buf, branch[i], 32); memcpy(buf + 32, cur, 32); }
        else                   { memcpy(buf, cur, 32); memcpy(buf + 32, branch[i], 32); }
        sha256(buf, 64, cur); sha256(cur, 32, cur);
    }
    return memcmp(cur, root, 32) == 0;
}
