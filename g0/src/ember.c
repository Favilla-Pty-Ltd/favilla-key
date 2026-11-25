/* ember.c — see ember.h. 28 Oct 2026. */
#include "ember.h"
#include "antiexfil.h"
#include "btc.h"
#include "sha256.h"
#include "secp256k1_recovery.h"
#include <string.h>

static void wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

static em_env_t E;
static const eh_params_t *g_params;
static eh_chain_t g_chain;
static eh_anchor_t g_floor;
static int g_has_plan, g_state_ok;
static es_plan_t g_plan;
static ep_set_t g_set;
static es_state_t g_st;
static uint32_t g_last_ms; static int g_last_quorum;
static uint32_t p_life, p_tip, p_ag;                     /* what the newest record holds */
static uint8_t g_stage[EM_STAGE_MAX]; static uint16_t g_stage_total; static uint32_t g_stage_have;

/* ── blobs ──────────────────────────────────────────────────────────────── */
static void blob_keys(const uint8_t blob_key[32], const uint8_t plan_id[32], uint8_t enc[32], uint8_t mac[32]) {
    uint8_t in[9 + 32];
    memcpy(in, "ember-enc", 9); memcpy(in + 9, plan_id, 32); hmac_sha256(blob_key, 32, in, sizeof in, enc);
    memcpy(in, "ember-mac", 9);                              hmac_sha256(blob_key, 32, in, sizeof in, mac);
}
static void keystream_xor(const uint8_t enc[32], uint16_t k, uint8_t *d, size_t n) {
    uint8_t in[4], ks[32];
    wr16(in, k);
    for (size_t off = 0, j = 0; off < n; off += 32, j++) {
        wr16(in + 2, (uint32_t)j); hmac_sha256(enc, 32, in, 4, ks);
        for (size_t i = 0; i < 32 && off + i < n; i++) d[off + i] ^= ks[i];
    }
    wipe(ks, 32);
}
static size_t blob_seal(const uint8_t blob_key[32], const uint8_t plan_id[32], uint16_t k, const uint8_t *pt, size_t n, uint8_t *out, size_t cap) {
    uint8_t enc[32], mac[32];
    if (8 + n + 32 > cap) return 0;
    memcpy(out, "EMB1", 4); wr16(out + 4, k); wr16(out + 6, (uint32_t)n);
    memcpy(out + 8, pt, n);
    blob_keys(blob_key, plan_id, enc, mac);
    keystream_xor(enc, k, out + 8, n);
    hmac_sha256(mac, 32, out, 8 + n, out + 8 + n);           /* "EMB1" | k | len | ciphertext */
    wipe(enc, 32); wipe(mac, 32);
    return 8 + n + 32;
}
static int blob_open(const uint8_t blob_key[32], const uint8_t plan_id[32], uint16_t want_k, const uint8_t *b, size_t len, uint8_t *out, size_t cap, size_t *n) {
    uint8_t enc[32], mac[32], tag[32]; int rc = EM_E_BLOB;
    if (len < 8 + 32 || memcmp(b, "EMB1", 4) != 0) return rc;
    uint16_t k = (uint16_t)(b[4] | (b[5] << 8)), cl = (uint16_t)(b[6] | (b[7] << 8));
    if (k != want_k || (size_t)cl + 40 != len || cl > cap) return rc;
    blob_keys(blob_key, plan_id, enc, mac);
    hmac_sha256(mac, 32, b, 8 + cl, tag);
    uint8_t diff = 0; for (int i = 0; i < 32; i++) diff |= tag[i] ^ b[8 + cl + i];
    if (diff == 0) { memcpy(out, b + 8, cl); keystream_xor(enc, k, out, cl); *n = cl; rc = EM_OK; }
    wipe(enc, 32); wipe(mac, 32);
    return rc;
}

/* ── persistence ────────────────────────────────────────────────────────── */
static uint32_t tip_h(void) { return eh_tip_height(&g_chain); }
static uint32_t conf_cb(void *u, const uint8_t hash[32]) { (void)u; return eh_find_main(&g_chain, hash, NULL); }

#ifdef EMBER_HOST_DEBUG
unsigned em_dbg_persist[4];
#endif
static int persist(int force) {
    if (!g_has_plan || !g_state_ok) return 0;
    uint32_t tip = tip_h(); const ew_state_t *w = &g_st.walk;
    if (!force && w->last_life < p_life + 144 && tip < p_tip + 2016 && w->ag_secs < p_ag + 3600) return 0;
#ifdef EMBER_HOST_DEBUG
    em_dbg_persist[force ? 0 : w->last_life >= p_life + 144 ? 1 : tip >= p_tip + 2016 ? 2 : 3]++;
#endif
    es_settle(&g_chain, EW_FINAL_DEPTH, &g_floor, &g_st.settled);
    if (es_state_append(&E.flash, g_plan.plan_id, &g_st)) return EM_E_FLASH;
    p_life = w->last_life; p_tip = tip; p_ag = w->ag_secs;
    return 0;
}
/* the walk fields whose change must reach flash at once */
typedef struct { uint32_t link; uint8_t adv, kindled, kvar, done_pending, done; } snap_t;
static snap_t snap(void) { const ew_state_t *w = &g_st.walk; snap_t s = { w->link, w->adv_pending, w->kindled, w->kvar, w->done_pending, w->done }; return s; }
static int changed(snap_t a) {   /* field by field: the struct has padding */
    snap_t b = snap();
    return a.link != b.link || a.adv != b.adv || a.kindled != b.kindled || a.kvar != b.kvar || a.done_pending != b.done_pending || a.done != b.done;
}

void em_boot(const em_env_t *env, const eh_params_t *params, const eh_anchor_t *compiled) {
    E = *env; g_params = params;
    g_floor = *compiled; g_has_plan = 0; g_state_ok = 0;
    memset(&g_st, 0, sizeof g_st);
    static const uint8_t no_plan[32] = {0};
    if (!es_plan_load(&E.flash, &g_plan) || ep_set_parse(g_plan.set_wire, EP_SET_LEN, &g_set) != EP_OK) {
        /* no plan: the clock may still have been saved (EMBER_SAVE) before a reboot */
        es_state_t s;
        if (es_state_load(&E.flash, no_plan, &s) && s.settled.height > g_floor.height) g_floor = s.settled;
    } else {
        g_has_plan = 1;
        if (es_state_load(&E.flash, g_plan.plan_id, &g_st)) {
            g_state_ok = 1;
            if (g_st.settled.height > g_floor.height) g_floor = g_st.settled;
            p_life = g_st.walk.last_life; p_tip = g_floor.height; p_ag = g_st.walk.ag_secs;
        }
    }
    eh_init(&g_chain, g_params, &g_floor);
    g_last_ms = E.ms(E.u); g_last_quorum = 0;
}

/* ── the clock ──────────────────────────────────────────────────────────── */
int em_header(const uint8_t in[EM_HDR_IN_LEN]) {
    uint32_t now = E.ms(E.u), secs = (now - g_last_ms) / 1000u;
    g_last_ms += secs * 1000u;
    int q = in[80] == 1;
    int rc = eh_connect(&g_chain, in);
    if (g_has_plan && g_state_ok) {
        snap_t s = snap(); uint32_t tip = tip_h();
        if (q && g_last_quorum) ew_tick(&g_st.walk, secs, 1, tip);
        if (rc == EH_TIP || rc == EH_REORG) ew_on_tip(&g_st.walk, tip, conf_cb, NULL);
        int e = persist(changed(s));
        if (e) rc = e;
        /* r7: the plan page is erased when the Kindling transaction is 6 deep */
        if (g_st.walk.done && em_clear()) rc = EM_E_FLASH;
    }
    g_last_quorum = q;
    return rc;
}

/* ── staging ────────────────────────────────────────────────────────────── */
int em_stage_begin(uint16_t total) {
    if (total == 0 || total > EM_STAGE_MAX) return EM_E_LEN;
    wipe(g_stage, sizeof g_stage); g_stage_total = total; g_stage_have = 0;
    return EM_OK;
}
int em_stage_chunk(uint16_t index, const uint8_t d[EM_CHUNK]) {
    uint32_t nchunks = (g_stage_total + EM_CHUNK - 1) / EM_CHUNK;
    if (!g_stage_total || index >= nchunks) return EM_E_LEN;
    uint32_t off = (uint32_t)index * EM_CHUNK, n = g_stage_total - off < EM_CHUNK ? g_stage_total - off : EM_CHUNK;
    for (uint32_t i = n; i < EM_CHUNK; i++) if (d[i]) return EM_E_LEN;   /* the last chunk's tail must be zero */
    memcpy(g_stage + off, d, n); g_stage_have |= 1u << index;
    return EM_OK;
}
static int staged(uint16_t want_len) {
    uint32_t nchunks = (g_stage_total + EM_CHUNK - 1) / EM_CHUNK;
    uint32_t all = nchunks >= 32 ? 0xFFFFFFFFu : ((1u << nchunks) - 1);
    return g_stage_total && g_stage_have == all && (want_len == 0 || g_stage_total == want_len);
}
static void stage_clear(void) { wipe(g_stage, sizeof g_stage); g_stage_total = 0; g_stage_have = 0; }
uint16_t em_stage_total(void) { return g_stage_total; }
void em_stage_reset(void) { stage_clear(); }

/* ── proofs, life, release ──────────────────────────────────────────────── */
int em_proof(void) {
    if (!g_has_plan || !g_state_ok) return EM_E_NOPLAN;
    if (!staged(EM_PROOF_LEN)) return EM_E_LEN;
    const uint8_t *b = g_stage, *hdr = b + 8;
    uint8_t kind = b[0], link = b[1], var = b[2], depth = b[3]; uint32_t index = rd32(b + 4);
    uint8_t hash[32]; uint32_t height, conf; const uint8_t *txid; int rc = EM_E_PROOF;
    eh_hash(hdr, hash);
    conf = eh_find_main(&g_chain, hash, &height);
    if (!conf) goto out;
    if (kind == 'R' && link >= 1 && link <= g_set.nlinks && var == 0) txid = g_plan.rtxid[link - 1];
    else if (kind == 'C' && link <= g_set.nlinks && var < EP_CVARS) txid = g_plan.ctxid[link][var];
    else goto out;
    if (!eh_merkle_check(txid, index, depth, (const uint8_t (*)[32])(b + 88), hdr + 36)) goto out;
    { snap_t s = snap();
      rc = ew_proof(&g_st.walk, (char)kind, link, hash, conf, height) ? EM_OK : EM_E_RULE;
      int e = persist(changed(s)); if (e) rc = e; }
out:
    stage_clear();
    return rc;
}

int em_life(const uint8_t sig[64]) {
    if (!g_has_plan || !g_state_ok) return EM_E_NOPLAN;
    if (!g_st.owner_set) { stage_clear(); return EM_E_OWNER; }
    if (!staged(0)) return EM_E_LEN;
    el_event_t ev; uint32_t h, tip = tip_h(); int rc;
    int t = el_check(E.ctx, g_stage, g_stage_total, sig, g_st.owner, &ev);
    stage_clear();
    if (t == EL_NOTE) {
        if ((rc = el_note_height(ev.created_at, tip, eh_tip(&g_chain)->time, g_chain.floor_height, &h))) return rc;
        ew_life(&g_st.walk, EW_LIFE_NOTE, h, tip);
    } else if (t == EL_PULSE) {
        if (!eh_find_main(&g_chain, ev.block, &h)) return EM_E_RULE;   /* pinned to a block this clock has not seen */
        ew_life(&g_st.walk, EW_LIFE_PULSE, h, tip);
    } else return t;
    return persist(0);
}

void em_life_tier1(const uint8_t owner[32]) {
    if (!g_has_plan || !g_state_ok) return;
    int force = 0;
    if (owner && !g_st.owner_set) { memcpy(g_st.owner, owner, 32); g_st.owner_set = 1; force = 1; }
    ew_life(&g_st.walk, EW_LIFE_TIER1, tip_h(), tip_h());
    persist(force);
}
void em_life_tier2(void) {
    if (!g_has_plan || !g_state_ok) return;
    ew_life(&g_st.walk, EW_LIFE_TIER2, tip_h(), tip_h());
    persist(0);
}
int em_away(uint32_t height) {
    if (!g_has_plan || !g_state_ok) return EM_E_NOPLAN;
    if (ew_life(&g_st.walk, EW_LIFE_AWAY, height, tip_h()) < 0) return EM_E_RULE;
    return persist(1);
}

uint32_t em_tx_count(void) { return ep_count(&g_set); }
uint32_t em_blob_index(ew_release_t r) {
    if (r.what == EW_REFRESH) return EP_CVARS + (r.link - 1) * (1 + EP_CVARS);
    return r.link == 0 ? r.var : EP_CVARS + (r.link - 1) * (1 + EP_CVARS) + 1 + r.var;
}

int em_release(uint8_t *out, size_t cap, size_t *outlen) {
    if (!g_has_plan || !g_state_ok) return EM_E_NOPLAN;
    if (!staged(0)) return EM_E_LEN;
    uint32_t tip = tip_h();
    ew_release_t r = ew_next(&g_st.walk, tip);
    int rc = EM_E_RULE;
    if (r.what != EW_NOTHING) {
        rc = blob_open(g_plan.blob_key, g_plan.plan_id, (uint16_t)em_blob_index(r), g_stage, g_stage_total, out, cap, outlen);
        if (rc == EM_OK) {
            snap_t s = snap();
            ew_released(&g_st.walk, r, tip);
            int e = persist(changed(s)); if (e) { wipe(out, *outlen); *outlen = 0; rc = e; }   /* nothing leaves unrecorded */
        }
    }
    stage_clear();
    return rc;
}

int em_pulse(uint8_t *ser, size_t cap, size_t *len, uint8_t id[32]) {
    if (!g_has_plan || !g_state_ok) return EM_E_NOPLAN;
    if (!g_st.owner_set) return EM_E_OWNER;
    if (!ew_pulse_allowed(&g_st.walk, tip_h())) return EM_E_RULE;
    const eh_ent_t *t = eh_tip(&g_chain);
    *len = el_pulse_serialise(g_st.owner, t->time, t->hash, ser, cap);
    if (!*len) return EM_E_LEN;
    sha256(ser, *len, id);
    return EM_OK;
}

void em_status(uint8_t o[EM_STATUS_LEN]) {
    const ew_state_t *w = &g_st.walk; uint32_t tip = tip_h();
    memset(o, 0, EM_STATUS_LEN);
    memcpy(o, "EMST", 4); o[4] = 1;                                   /* version */
    o[5] = (uint8_t)(g_has_plan | (g_state_ok << 1) | (g_st.owner_set << 2) | (ew_silent(w, tip) << 3) |
                     (ew_afterglow_served(w, tip) << 4) | (w->kindled << 5) | (w->done << 6) | (w->adv_pending << 7));
    o[6] = (uint8_t)w->link; o[7] = (uint8_t)w->nlinks;
    wr32(o + 8, tip); wr32(o + 12, eh_tip(&g_chain)->time);
    wr32(o + 16, g_has_plan ? ew_x(w, w->link) : 0);
    wr32(o + 20, w->last_life); wr32(o + 24, w->last_tier1); wr32(o + 28, w->last_pulse);
    wr32(o + 32, w->ag_secs); wr32(o + 36, w->quiet); wr32(o + 40, g_floor.height);
    ew_release_t r = g_has_plan && g_state_ok ? ew_next(w, tip) : (ew_release_t){ 0, 0, 0 };
    o[44] = (uint8_t)r.what; o[45] = (uint8_t)r.link; o[46] = (uint8_t)r.var; o[47] = w->kvar;
    memcpy(o + 48, eh_tip(&g_chain)->hash, 32);
    if (g_has_plan) memcpy(o + 80, g_plan.plan_id, 15);   /* byte 95 is the boot KAT (ember_glue.inc) */
}

/* EMBER_SAVE: write the clock's restart point now (the block 6 below the tip),
 * so a reboot (into a Bitcoin life with no radio, say) starts from it. With a
 * plan this is an ordinary forced state write; without one, a record under an
 * all-zero plan id that holds only the restart point. Skipped when the restart
 * point has not moved since the last save, so it cannot be used to wear flash. */
int em_save(void) {
    static const uint8_t no_plan[32] = {0};
    eh_anchor_t s; es_settle(&g_chain, EW_FINAL_DEPTH, &g_floor, &s);
    if (g_has_plan && g_state_ok) {
        if (s.height == g_st.settled.height) return EM_OK;
        return persist(1);
    }
    if (g_has_plan) return EM_E_STATE;
    es_state_t cur;
    if (es_state_load(&E.flash, no_plan, &cur) && cur.settled.height >= s.height) return EM_OK;
    if (s.height == g_floor.height && !es_state_load(&E.flash, no_plan, &cur)) {
        /* nothing settled beyond the compiled anchor yet: nothing worth saving */
        return EM_OK;
    }
    memset(&cur, 0, sizeof cur); cur.settled = s;
    return es_state_append(&E.flash, no_plan, &cur) ? EM_E_FLASH : EM_OK;
}

int em_clear(void) {
    int a = es_state_erase(&E.flash), b = es_plan_erase(&E.flash);
    g_has_plan = 0; g_state_ok = 0; memset(&g_st, 0, sizeof g_st); wipe(&g_plan, sizeof g_plan);
    return (a || b) ? EM_E_FLASH : EM_OK;
}

/* ── ceremony ───────────────────────────────────────────────────────────── */
static struct {
    int active, pending; uint32_t n, k; uint8_t input;
    es_plan_t plan; ep_set_t set; uint32_t tip0;
    uint8_t cpub[EP_MAX_COINS][33], rpub[EP_MAX_LINKS][33];
    et_tx_t tx; uint8_t key[32], pub[33], sh[32], k0[32], r0[33];
    uint8_t sig[ET_MAX_IN][ET_SIG_MAX]; uint8_t siglen[ET_MAX_IN];
} C;

void em_cer_abort(void) { wipe(&C, sizeof C); }

int em_set(const uint8_t wire[EP_SET_LEN]) {
    em_cer_abort();
    if (!E.leaf || !E.rand32) return EM_E_CEREMONY;
    if (ep_set_parse(wire, EP_SET_LEN, &C.set) != EP_OK) return EM_E_PLAN;
    uint32_t tip = tip_h();
    if (ep_validate(&C.set, tip) != EP_OK) { em_cer_abort(); return EM_E_PLAN; }
    uint8_t k[32]; int rc = EM_E_CEREMONY;
    for (int i = 0; i < C.set.ncoins; i++)
        if (E.leaf(E.u, C.set.coin[i].change, C.set.coin[i].index, k, C.cpub[i])) goto fail;
    for (uint32_t i = 0; i < C.set.nlinks; i++)
        if (E.leaf(E.u, 0, C.set.ref_index + i, k, C.rpub[i])) goto fail;
    wipe(k, 32);
    C.tip0 = tip; C.n = ep_count(&C.set);
    for (uint32_t j = 0; j < C.n; j++) {
        ep_id_t id = ep_id_at(j); et_tx_t tx;
        if (ep_build(&C.set, tip, (const uint8_t (*)[33])C.cpub, (const uint8_t (*)[33])C.rpub, id, &tx)) goto fail;
        et_txid(&tx, id.kind == 'R' ? C.plan.rtxid[id.link - 1] : C.plan.ctxid[id.link][id.var]);
    }
    memcpy(C.plan.set_wire, wire, EP_SET_LEN);
    E.rand32(E.u, C.plan.plan_id); E.rand32(E.u, C.plan.blob_key);
    C.plan.tip0 = tip; C.plan.x0 = ep_x(&C.set, tip, 0);
    C.active = 1;
    return EM_OK;
fail:
    wipe(k, 32); em_cer_abort(); return rc;
}

/* key for the input that pays to pub: an estate coin or an owner refresh address */
static int key_for(const uint8_t pub[33], uint8_t key[32]) {
    uint8_t p[33];
    for (int i = 0; i < C.set.ncoins; i++)
        if (!memcmp(pub, C.cpub[i], 33)) return E.leaf(E.u, C.set.coin[i].change, C.set.coin[i].index, key, p) || memcmp(p, pub, 33) ? -1 : 0;
    for (uint32_t i = 0; i < C.set.nlinks; i++)
        if (!memcmp(pub, C.rpub[i], 33)) return E.leaf(E.u, 0, C.set.ref_index + i, key, p) || memcmp(p, pub, 33) ? -1 : 0;
    return -1;
}

int em_cer_init(const uint8_t h[32], uint8_t r0[33], uint16_t *k, uint8_t *input) {
    if (!C.active || C.pending || C.k >= C.n) return EM_E_CEREMONY;
    ep_id_t id = ep_id_at(C.k);
    if (ep_build(&C.set, C.tip0, (const uint8_t (*)[33])C.cpub, (const uint8_t (*)[33])C.rpub, id, &C.tx)) { em_cer_abort(); return EM_E_CEREMONY; }
    memcpy(C.pub, C.tx.in[C.input].pub, 33);
    et_sighash(&C.tx, C.input, C.sh);
    if (key_for(C.pub, C.key) || ae_ecdsa_init(E.ctx, C.key, C.sh, h, C.k0, C.r0)) { em_cer_abort(); return EM_E_AE; }
    memcpy(r0, C.r0, 33); *k = (uint16_t)C.k; *input = C.input;
    C.pending = 1;
    return EM_OK;
}

int em_cer_finish(const uint8_t t[32], uint8_t r32[32], uint8_t *blob, size_t cap, size_t *blob_len) {
    secp256k1_ecdsa_signature sig; uint8_t der[BTC_DER_MAX], dl = 0, c64[64];
    *blob_len = 0;
    if (!C.active || !C.pending) return EM_E_CEREMONY;
    C.pending = 0;
    int ok = ae_ecdsa_finish(E.ctx, AE_KIND_ECDSA, C.key, C.sh, C.k0, C.r0, t, &sig, NULL) == 0 &&
             btc_sign_release(E.ctx, C.key, C.sh, C.pub, &sig, der, &dl) == 0;
    wipe(C.key, 32); wipe(C.k0, 32);
    if (!ok) { em_cer_abort(); return EM_E_AE; }
    secp256k1_ecdsa_signature_serialize_compact(E.ctx, c64, &sig);
    if (!ae_host_check(E.ctx, AE_KIND_ECDSA, C.r0, t, c64)) { em_cer_abort(); return EM_E_AE; }   /* self-check, as the host will */
    memcpy(r32, c64, 32);
    memcpy(C.sig[C.input], der, dl); C.sig[C.input][dl] = 0x01; C.siglen[C.input] = (uint8_t)(dl + 1);
    if (++C.input < C.tx.nin) return EM_OK;
    /* transaction complete: witness in, sealed, out */
    for (int i = 0; i < C.tx.nin; i++) { memcpy(C.tx.in[i].sig, C.sig[i], C.siglen[i]); C.tx.in[i].siglen = C.siglen[i]; }
    static uint8_t raw[1100];
    size_t n = et_serialize(&C.tx, 1, raw, sizeof raw);
    if (n > sizeof raw) { em_cer_abort(); return EM_E_CEREMONY; }
    *blob_len = blob_seal(C.plan.blob_key, C.plan.plan_id, (uint16_t)C.k, raw, n, blob, cap);
    wipe(raw, sizeof raw); wipe(C.sig, sizeof C.sig);
    if (!*blob_len) { em_cer_abort(); return EM_E_LEN; }
    C.k++; C.input = 0;
    return EM_OK;
}

int em_commit(void) {
    if (!C.active || C.pending || C.k != C.n) return EM_E_CEREMONY;
    int rc = EM_E_FLASH;
    if (es_state_erase(&E.flash)) goto out;
    if (es_plan_write(&E.flash, &C.plan)) goto out;
    g_plan = C.plan; g_set = C.set; g_has_plan = 1;
    memset(&g_st, 0, sizeof g_st);
    ew_init(&g_st.walk, C.set.nlinks, C.set.quiet, C.plan.x0, C.tip0);
    g_state_ok = 1;
    if (persist(1)) { g_state_ok = 0; goto out; }
    rc = EM_OK;
out:
    em_cer_abort();
    return rc;
}

int em_cer_peek(uint8_t sh[32], uint8_t *tx, size_t cap, size_t *txlen) {
    *txlen = 0;
    if (!C.active || !C.pending) return EM_E_CEREMONY;
    memcpy(sh, C.sh, 32);
    if (C.input == 0) {
        size_t n = et_serialize(&C.tx, 0, tx, cap);
        if (n > cap) return EM_E_LEN;
        *txlen = n;
    }
    return EM_OK;
}
uint32_t em_cer_tip0(void) { return C.active ? C.tip0 : 0; }

void em_cer_counts(uint32_t *ntx, uint32_t *nsig) {
    *ntx = C.active ? C.n : 0;
    /* C0 x3 and R1 spend every coin; R2..RN one input each; C1..CN x3 one input each */
    *nsig = C.active ? 4u * C.set.ncoins + 4u * C.set.nlinks - 1u : 0;
}

const ew_state_t *em_walk(void) { return &g_st.walk; }
const eh_chain_t *em_chain(void) { return &g_chain; }
