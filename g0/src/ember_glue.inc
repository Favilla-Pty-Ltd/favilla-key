/* =============================================================================
 * ember_glue.inc — Emberwill in the G0's register file. 28 Oct 2026.
 * Included once by main.c, after the signing handlers and before commit_write().
 * The logic lives in src/ember*.c (host-tested); this file only moves bytes,
 * gates doors, fetches the seed / scalar through the existing paths and runs
 * the anti-exfil exchange for the ceremony and for Pulses.
 *
 * REGISTERS (invariant 1: exact length or dropped)
 *   0x1B EM_HDR   W 81   header 80 | quorum 1 (1 = the ESP32 sees its relay quorum)
 *   0x1C EM_SET   W 430  EMBER_SET body (src/ember_plan.c ep_set_parse)
 *   0x1D EM_CHUNK W 68   total 2 | index 2 | 64 bytes: stages an event, blob or proof
 *   0x1E EM_ARG   W 64   EMBER_LIFE signature, or EMBER_AWAY height in bytes 0..3 (rest zero)
 *   0x1F EM_OUT   R      rc (int8) | len (u16 LE) | payload, readable in SIG_READY
 * COMMANDS (every one answers SIG_READY with rc in EM_OUT[0]; the diag is the result)
 *   0x30 EM_HEADER    any door      EM_HDR -> rc = EH_* code, payload = status (96, src/ember.c em_status;
 *                                   byte 95 = boot KAT)
 *   0x31 EM_SET       BTC door      SEED_IN/ENT_IN + EM_SET: fetch seed (spend PIN), hold
 *                                   the account key, validate, build every transaction;
 *                                   payload = transactions (1) | signatures (1) | v20: ceremony tip (4 LE)
 *   0x32 EM_CER_INIT  BTC door      AE_IN = zeros(32) || h -> k (2) | input (1) | R0 (33)
 *                                   | v20: sighash (32) | txlen (2 LE) | unsigned tx (txlen,
 *                                   on a transaction's first input only, else 0)
 *   0x33 EM_CER_FIN   BTC door      AE_T = t -> r (32) | blob_len (2) | blob
 *   0x34 EM_COMMIT    BTC door      write the plan page and the first state record
 *   0x35 EM_PROOF     any door      stage = kind | link | var | depth | index4 | header80 | branch
 *   0x36 EM_LIFE      any door      stage = serialised event, EM_ARG = signature
 *   0x37 EM_STATUS    any door      payload = status (96)
 *   0x38 EM_RELEASE   not BTC       stage = blob -> payload = signed transaction
 *   0x39 EM_PULSE     not BTC       AE_IN = zeros(32) || h -> R0 (33) | len (2) | event;
 *                                   then AE_FINISH as for SIGN_INIT -> SIG_OUT = signature
 *   0x3A EM_CLEAR     BTC door      erase the plan
 *   0x3B EM_AWAY      not BTC       EM_ARG height; needs a tier-1 event this power-on life
 *   0x3C EM_SAVE      any door      write the clock's restart point (tip - 6) now; the ESP32
 *                                   sends it before rebooting into a Bitcoin life
 * ========================================================================== */
#include "ember.h"
#include "ember_anchor.h"

#define G0_REG_EM_HDR    0x1B
#define G0_REG_EM_SET    0x1C
#define G0_REG_EM_CHUNK  0x1D
#define G0_REG_EM_ARG    0x1E
#define G0_REG_EM_OUT    0x1F
#define EM_CHUNK_IN_LEN  (4u + EM_CHUNK)
#define EM_ARG_LEN       64u
#define EM_OUT_MAX       (3u + EM_BLOB_MAX + 34u)

#define G0_CMD_EM_HEADER   0x30
#define G0_CMD_EM_SET      0x31
#define G0_CMD_EM_CER_INIT 0x32
#define G0_CMD_EM_CER_FIN  0x33
#define G0_CMD_EM_COMMIT   0x34
#define G0_CMD_EM_PROOF    0x35
#define G0_CMD_EM_LIFE     0x36
#define G0_CMD_EM_STATUS   0x37
#define G0_CMD_EM_RELEASE  0x38
#define G0_CMD_EM_PULSE    0x39
#define G0_CMD_EM_CLEAR    0x3A
#define G0_CMD_EM_AWAY     0x3B
#define G0_CMD_EM_SAVE     0x3C
#define EM_CER_TIMEOUT_MS  120000u     /* the account key is forgotten 2 min after the last ceremony step */

static uint8_t g_em_hdr[EM_HDR_IN_LEN]; static volatile uint8_t g_em_hdr_valid = 0;
static uint8_t g_em_set[EP_SET_LEN];    static volatile uint8_t g_em_set_valid = 0;
static uint8_t g_em_arg[EM_ARG_LEN];    static volatile uint8_t g_em_arg_valid = 0;
static uint8_t g_em_out[EM_OUT_MAX];    static uint16_t g_em_out_len = 0;
static btc_xprv g_em_acct; static uint8_t g_em_acct_ok = 0; static uint32_t g_em_t0 = 0;
static uint8_t g_em_h[32];             /* the ceremony signature's commitment, checked against t at FIN */
static uint8_t g_tier1_this_life = 0;  /* a PIN-gated fetch happened since this physical boot */
static volatile uint32_t g_ecc_faults = 0;

/* ── environment for src/ember.c ── */
static int em_f_erase(void *c, uint32_t a) { (void)c; return ks_flash_erase_page(a); }
static int em_f_prog(void *c, uint32_t a, const uint8_t *d, size_t n) { (void)c; return ks_flash_program(a, d, n); }
static const uint8_t *em_f_map(void *c, uint32_t a) { (void)c; return (const uint8_t *)a; }
static uint32_t em_ms(void *u) { (void)u; return HAL_GetTick(); }
static void em_rand(void *u, uint8_t out[32]) {
    static const uint8_t label[] = "favilla-g0-ember-rand";
    (void)u; entropy_mix(label, sizeof(label) - 1);
    sha256_ctx c; sha256_init(&c); sha256_update(&c, g_pool, 32); sha256_update(&c, g_kg0, KG0_LEN); sha256_final(&c, out);
    entropy_mix(out, 32);
}
static int em_leaf(void *u, uint32_t ch, uint32_t ix, uint8_t key[32], uint8_t pub[33]) {
    (void)u; if (!g_em_acct_ok) return -1;
    return btc_leaf(g_ctx, &g_em_acct, ch, ix, key, pub);
}
/* Boot KAT (28 Oct 2026): the header clock and Merkle check on this silicon,
 * against mainnet facts: the genesis block id, Bitcoin Core's pow_tests
 * retarget at 32256, and block 170's Merkle root from its two txids.
 * Reported in EM_STATUS byte 95 (1 = pass); the ESP32 refuses Emberwill on 0. */
static uint8_t g_em_kat = 0;
static void em_glue_kat(void) {
    static const uint8_t GEN[80] = {
        0x01,0x00,0x00,0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
        0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
        0x29,0xab,0x5f,0x49, 0xff,0xff,0x00,0x1d, 0x1d,0xac,0x2b,0x7c };
    static const uint8_t GEN_ID[32] = {
        0x6f,0xe2,0x8c,0x0a,0xb6,0xf1,0xb3,0x72,0xc1,0xa6,0xa2,0x46,0xae,0x63,0xf7,0x4f,
        0x93,0x1e,0x83,0x65,0xe1,0x5a,0x08,0x9c,0x68,0xd6,0x19,0x00,0x00,0x00,0x00,0x00 };
    static const uint8_t B170_TX0[32] = {0x82,0x50,0x1c,0x11,0x78,0xfa,0x0b,0x22,0x2c,0x1f,0x3d,0x47,0x4e,0xc7,0x26,0xb8,0x32,0x01,0x3f,0x0a,0x53,0x2b,0x44,0xbb,0x62,0x0c,0xce,0x86,0x24,0xa5,0xfe,0xb1};
    static const uint8_t B170_TX1[1][32] = { {0x16,0x9e,0x1e,0x83,0xe9,0x30,0x85,0x33,0x91,0xbc,0x6f,0x35,0xf6,0x05,0xc6,0x75,0x4c,0xfe,0xad,0x57,0xcf,0x83,0x87,0x63,0x9d,0x3b,0x40,0x96,0xc5,0x4f,0x18,0xf4} };
    static const uint8_t B170_ROOT[32] = {0xff,0x10,0x4c,0xcb,0x05,0x42,0x1a,0xb9,0x3e,0x63,0xf8,0xc3,0xce,0x5c,0x2c,0x2e,0x9d,0xbb,0x37,0xde,0x27,0x64,0xb3,0xa3,0x17,0x5c,0x81,0x66,0x56,0x2c,0xac,0x7d};
    uint8_t h[32];
    eh_hash(GEN, h);
    g_em_kat = memcmp(h, GEN_ID, 32) == 0 &&
               eh_retarget(&EH_MAINNET, 0x1d00ffff, 1261130161, 1262152739) == 0x1d00d86a &&
               eh_merkle_check(B170_TX0, 0, 1, B170_TX1, B170_ROOT) &&
               !eh_merkle_check(B170_TX0, 1, 1, B170_TX1, B170_ROOT);
}
static void em_glue_boot(void) {
    em_env_t env = { g_ctx, { em_f_erase, em_f_prog, em_f_map, NULL }, em_ms, em_rand, em_leaf, NULL };
    em_boot(&env, &EH_MAINNET, &EMBER_ANCHOR);
    em_glue_kat();
}

/* A torn doubleword in a flash page (power cut mid-program) raises an ECC
 * double-error NMI when read. Every Emberwill record and the key/seed pages
 * carry digests, so the bad bytes are rejected anyway: acknowledge and go on.
 * Anything else that raises an NMI stops the core as before. */
void NMI_Handler(void) {
    if (FLASH->ECCR & FLASH_ECCR_ECCD) { FLASH->ECCR |= FLASH_ECCR_ECCD; g_ecc_faults++; return; }
    for (;;) { }
}

/* tier-1 life: every successful PIN-gated fetch (r7 "Life is a height") */
static void em_glue_tier1(int nostr) {
    uint8_t x[32];
    g_tier1_this_life = 1;
    if (nostr && g_true_pk_ok && secp256k1_xonly_pubkey_serialize(g_ctx, x, &g_true_pk)) em_life_tier1(x);
    else em_life_tier1(NULL);
}

static void em_acct_wipe(void) { secure_wipe(&g_em_acct, sizeof(g_em_acct)); g_em_acct_ok = 0; }
static void em_glue_abort(void) { em_cer_abort(); em_acct_wipe(); secure_wipe(g_em_h, 32); }
static void em_glue_tick(void) { if (g_em_acct_ok && HAL_GetTick() - g_em_t0 > EM_CER_TIMEOUT_MS) em_glue_abort(); }
static void em_glue_wipe_inputs(void) {
    secure_wipe(g_em_hdr, sizeof(g_em_hdr)); g_em_hdr_valid = 0;
    secure_wipe(g_em_set, sizeof(g_em_set)); g_em_set_valid = 0;
    secure_wipe(g_em_arg, sizeof(g_em_arg)); g_em_arg_valid = 0;
}
static void em_glue_wipe_transient(void) { em_glue_wipe_inputs(); em_stage_reset(); em_glue_abort(); secure_wipe(g_em_out, sizeof(g_em_out)); g_em_out_len = 0; }

static void em_out(int rc, const uint8_t *p, size_t n) {
    if (n > EM_OUT_MAX - 3u) n = 0;
    g_em_out[0] = (uint8_t)(int8_t)rc; g_em_out[1] = (uint8_t)n; g_em_out[2] = (uint8_t)(n >> 8);
    if (n) memcpy(g_em_out + 3, p, n);
    g_em_out_len = (uint16_t)n;
}

static int do_em(uint8_t cmd) {
    static uint8_t buf[EM_OUT_MAX];
    int rc = EM_OK; size_t n = 0;
    secure_wipe(g_em_out, sizeof(g_em_out)); g_em_out_len = 0;
    switch (cmd) {
    case G0_CMD_EM_HEADER:
        if (!g_em_hdr_valid) { rc = EM_E_LEN; break; }
        rc = em_header(g_em_hdr); em_status(buf); buf[95] = g_em_kat; n = EM_STATUS_LEN;
        break;
    case G0_CMD_EM_STATUS:
        em_status(buf); buf[95] = g_em_kat; n = EM_STATUS_LEN;
        break;
    case G0_CMD_EM_SET: {
        uint8_t seed[64]; int step = 0; uint8_t d[8] = {0};
        em_glue_abort();
        if (!g_em_set_valid) { rc = EM_E_LEN; break; }
        uint8_t gr = get_seed(seed, &step, d);         /* spend PIN, MODE_PCR == BTC; stamps tier-1 */
        if (gr) { secure_wipe(seed, 64); buf[0] = gr; n = 1; rc = EM_E_CEREMONY; break; }
        if (btc_account(g_ctx, seed, 84, &g_em_acct, NULL, NULL) == 0) g_em_acct_ok = 1;
        secure_wipe(seed, 64);
        if (!g_em_acct_ok) { rc = EM_E_CEREMONY; break; }
        g_em_t0 = HAL_GetTick();
        rc = em_set(g_em_set);
        if (rc) em_glue_abort();
        else { uint32_t nt, ns, t0 = em_cer_tip0(); em_cer_counts(&nt, &ns); buf[0] = (uint8_t)nt; buf[1] = (uint8_t)ns;
               buf[2] = (uint8_t)t0; buf[3] = (uint8_t)(t0 >> 8); buf[4] = (uint8_t)(t0 >> 16); buf[5] = (uint8_t)(t0 >> 24); n = 6; }   /* v20: + ceremony tip */
        break; }
    case G0_CMD_EM_CER_INIT: {
        uint16_t k = 0; uint8_t in = 0;
        if (!g_em_acct_ok || !g_ae_in_valid || !ae_in_msg_is_zero() || g_ae.kind != AE_KIND_NONE) { rc = EM_E_CEREMONY; break; }
        memcpy(g_em_h, g_ae_in + 32, 32);
        { uint8_t hx[32]; hedge32("favilla-g0-ecdsa-hedge", g_em_h, hx);   /* v18: hedged nonce; ember checks t against its own copy of h, not this */
          rc = em_cer_init(hx, buf + 3, &k, &in); secure_wipe(hx, 32); }
        if (rc == EM_E_AE) { em_glue_abort(); break; }      /* a failed commitment ends the ceremony */
        if (rc) break;                                       /* out of turn (e.g. all signed): refused, ceremony kept */
        buf[0] = (uint8_t)k; buf[1] = (uint8_t)(k >> 8); buf[2] = in; n = 36;
        { size_t tl = 0;   /* v20: what is about to be signed, for the ESP32's own check (never a signature) */
          if (em_cer_peek(buf + 36, buf + 70, sizeof(buf) - 70, &tl) != EM_OK) { em_glue_abort(); rc = EM_E_CEREMONY; n = 0; break; }
          buf[68] = (uint8_t)tl; buf[69] = (uint8_t)(tl >> 8); n = 70 + tl; }
        g_em_t0 = HAL_GetTick();
        break; }
    case G0_CMD_EM_CER_FIN: {
        uint8_t h2[32]; size_t bl = 0;
        if (!g_em_acct_ok || !g_ae_t_valid) { rc = EM_E_CEREMONY; break; }
        ae_host_commit(AE_KIND_ECDSA, g_ae_t, h2);
        if (memcmp(h2, g_em_h, 32) != 0) { em_glue_abort(); rc = EM_E_AE; break; }   /* t must open the commitment */
        rc = em_cer_finish(g_ae_t, buf, buf + 34, sizeof(buf) - 34, &bl);
        if (rc) { em_glue_abort(); break; }
        buf[32] = (uint8_t)bl; buf[33] = (uint8_t)(bl >> 8); n = 34 + bl;
        g_em_t0 = HAL_GetTick();
        break; }
    case G0_CMD_EM_COMMIT:
        rc = em_commit(); em_acct_wipe();
        break;
    case G0_CMD_EM_PROOF:
        rc = em_proof();
        break;
    case G0_CMD_EM_LIFE:
        if (!g_em_arg_valid) { rc = EM_E_LEN; break; }
        rc = em_life(g_em_arg);
        break;
    case G0_CMD_EM_RELEASE:
        rc = em_release(buf, sizeof(buf), &n);
        if (rc) n = 0;
        break;
    case G0_CMD_EM_AWAY: {
        uint8_t z = 0; for (unsigned i = 4; i < EM_ARG_LEN; i++) z |= g_em_arg[i];
        if (!g_em_arg_valid || z) { rc = EM_E_LEN; break; }
        if (!g_tier1_this_life) { rc = EM_E_RULE; break; }        /* r7: PIN in person, this power-on life */
        rc = em_away((uint32_t)g_em_arg[0] | ((uint32_t)g_em_arg[1] << 8) | ((uint32_t)g_em_arg[2] << 16) | ((uint32_t)g_em_arg[3] << 24));
        break; }
    case G0_CMD_EM_CLEAR:
        em_glue_abort(); rc = em_clear();
        break;
    case G0_CMD_EM_SAVE:
        rc = em_save();
        break;
    case G0_CMD_EM_PULSE: {
        /* build the Pulse inside the G0, then sign its id exactly as SIGN_INIT does */
        uint8_t ser[256], id[32], scalar[32], aux[32]; size_t sl = 0;
        if (!g_ae_in_valid || !ae_in_msg_is_zero() || g_ae.kind != AE_KIND_NONE || !g_true_pk_ok) { rc = EM_E_AE; break; }
        rc = em_pulse(ser, sizeof(ser), &sl, id);
        if (rc) break;
        if (fetch_scalar(scalar) != 0) { rc = EM_E_AE; break; }
        { static const uint8_t label[] = "favilla-g0-bip340-aux"; uint8_t fresh[32]; sha256_ctx c;
          entropy_mix(label, sizeof(label) - 1); sha256(g_pool, 32, fresh);
          sha256_init(&c); sha256_update(&c, g_kg0, KG0_LEN); sha256_update(&c, id, 32); sha256_update(&c, fresh, 32); sha256_final(&c, aux);
          secure_wipe(fresh, 32); }
        if (ae_schnorr_init(g_ctx, scalar, id, aux, g_ae_in + 32, g_ae.k0, g_ae.r0) == 0) {
            memcpy(g_ae.key, scalar, 32); memcpy(g_ae.h, g_ae_in + 32, 32); memcpy(g_ae.msg, id, 32);
            g_ae.t0 = HAL_GetTick(); g_ae.kind = AE_KIND_SCHNORR;
            memcpy(buf, g_ae.r0, 33); buf[33] = (uint8_t)sl; buf[34] = (uint8_t)(sl >> 8); memcpy(buf + 35, ser, sl); n = 35 + sl;
        } else { ae_wipe(); rc = EM_E_AE; }
        secure_wipe(scalar, 32); secure_wipe(aux, 32);
        break; }
    default: rc = -1; break;
    }
    em_out(rc, buf, n);
    secure_wipe(buf, sizeof(buf));
    em_glue_wipe_inputs();
    return 0;   /* the diag is the result */
}

static int em_cmd(uint8_t c) { return c >= G0_CMD_EM_HEADER && c <= G0_CMD_EM_SAVE; }
/* door rules for the Emberwill commands; -1 = not an Emberwill command */
static int em_door_permits(uint8_t c) {
    switch (c) {
    case G0_CMD_EM_SET: case G0_CMD_EM_CER_INIT: case G0_CMD_EM_CER_FIN: case G0_CMD_EM_COMMIT: case G0_CMD_EM_CLEAR:
        return g_door == DOOR_BTC;
    case G0_CMD_EM_RELEASE: case G0_CMD_EM_PULSE: case G0_CMD_EM_AWAY:
        return g_door == DOOR_UNSET || g_door == DOOR_NOSTR;   /* 30 Oct 2026 (generic doors): was "!= DOOR_BTC", which admitted a PASSKEY life */
    case G0_CMD_EM_HEADER: case G0_CMD_EM_PROOF: case G0_CMD_EM_LIFE: case G0_CMD_EM_STATUS: case G0_CMD_EM_SAVE:
        return 1;
    default: return -1;
    }
}
/* ISR side: register writes (called from commit_write when accepting()) */
static int em_commit_write(uint8_t reg, const uint8_t *p, size_t plen) {
    switch (reg) {
    case G0_REG_EM_HDR: if (plen == EM_HDR_IN_LEN) { memcpy(g_em_hdr, p, EM_HDR_IN_LEN); g_em_hdr_valid = 1; } return 1;
    case G0_REG_EM_SET: if (plen == EP_SET_LEN) { memcpy(g_em_set, p, EP_SET_LEN); g_em_set_valid = 1; } return 1;
    case G0_REG_EM_ARG: if (plen == EM_ARG_LEN) { memcpy(g_em_arg, p, EM_ARG_LEN); g_em_arg_valid = 1; } return 1;
    case G0_REG_EM_CHUNK:
        if (plen == EM_CHUNK_IN_LEN) {
            uint16_t total = (uint16_t)(p[0] | (p[1] << 8)), idx = (uint16_t)(p[2] | (p[3] << 8));
            if (idx == 0) em_stage_begin(total);
            if (total == em_stage_total()) em_stage_chunk(idx, p + 4);
        }
        return 1;
    default: return 0;
    }
}
