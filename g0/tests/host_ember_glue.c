/* host_ember_glue.c — src/ember_glue.inc (the Emberwill register file and
 * command glue) together with the anti-exfil handlers EXTRACTED VERBATIM from
 * src/main.c, driven the way the ESP32 will drive them. 28 Oct 2026.
 *
 *  R  register lengths: every Emberwill register accepts exactly its length
 *  D  door table: BTC-only, not-BTC and any-door commands
 *  C  ceremony over the registers: EM_SET (seed fetch = tier 1), EM_CER_INIT /
 *     EM_CER_FIN with the host relation on every signature, wrong t aborts the
 *     ceremony, the account key is forgotten after the 2-minute idle timeout,
 *     EM_COMMIT
 *  N  Nostr life: the first fetch binds the owner key; EM_PULSE builds the
 *     Pulse and AE_FINISH signs it (host relation + BIP-340 verify); the signed
 *     Pulse goes back in through EM_CHUNK + EM_LIFE; EM_AWAY needs tier 1 this
 *     life and a zero tail
 *  W  the walk through the registers: EM_HDR feeds, EM_RELEASE of R1 through
 *     EM_CHUNK in its window (refused in the BTC door), EM_PROOF advances
 *  X  EM_CLEAR (BTC door) erases the plan
 * Run tests/run_ember_glue.sh from the project root. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_recovery.h"
#include "secp256k1_preallocated.h"
#include "sha256.h"
#include "antiexfil.h"
#include "btc.h"
void secp256k1_default_illegal_callback_fn(const char *m, void *d){(void)d;printf("ILLEGAL: %s\n",m);}
void secp256k1_default_error_callback_fn(const char *m, void *d){(void)d;printf("ERROR: %s\n",m);}

/* ---- the slice of main.c these handlers touch (as host_antiexfil_cmd.c) -- */
#include "extracted_ae_defs.inc"
#define DOOR_UNSET 0
#define DOOR_NOSTR 1
#define DOOR_BTC   2
#define DOOR_PASSKEY 3       /* 30 Oct 2026: generic doors */
#define G0_CMD_MODEDOOR 0x21
#define G0_CMD_PKSIGN 0x22   /* restorable passkeys, 30 Oct 2026 */
#define G0_CMD_VAULT 0x28    /* vault records, 2 Nov 2026 */
static uint8_t g_door = DOOR_UNSET;
static secp256k1_context *g_ctx; static uint8_t g_ctxbuf[512] __attribute__((aligned(16)));
static void secure_wipe(void *p, size_t n){ volatile uint8_t *v = p; while(n--) *v++ = 0; }
static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint32_t g_tick = 1000;
static uint32_t HAL_GetTick(void) { return g_tick; }
static uint8_t g_kg0[KG0_LEN], g_pool[32];
static void entropy_mix(const uint8_t *d, size_t n){ sha256_ctx c; sha256_init(&c); sha256_update(&c, g_pool, 32); if(d&&n) sha256_update(&c, d, n); g_tick++; sha256_update(&c,(const uint8_t*)&g_tick,4); sha256_final(&c, g_pool); }
#include "hedge.inc"   /* v18: the firmware's own hedge32 */
static void ctx_reblind(void){ unsigned char sd[32]; memset(sd, 7, 32); (void)secp256k1_context_randomize(g_ctx, sd); }
static uint8_t g_sig_out[64], g_btc_out[BTC_OUT_LEN];
static uint8_t g_btc_in[BTC_REQ_LEN]; static uint8_t g_btc_in_valid = 0;
static const uint8_t SK[32] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x12};
static void em_glue_tier1(int nostr);
static int fetches = 0;
static int fetch_scalar(uint8_t s[32]){ fetches++; memcpy(s, SK, 32); em_glue_tier1(1); return 0; }   /* as main.c: tier 1 on success */
static uint8_t SEED[64]; static int burns = 0;
static uint8_t get_seed(uint8_t seed[64], int *step, uint8_t d[8]) { (void)step; (void)d; burns++; memcpy(seed, SEED, 64); em_glue_tier1(0); return 0; }
#include "extracted_ae_state.inc"
#include "extracted_ae_sign.inc"
#include "extracted_ae_btc.inc"
/* FLASH ECC register for the NMI handler, and the Emberwill pages in RAM */
typedef struct { volatile uint32_t ECCR; } flash_regs_t; static flash_regs_t g_flash_regs;
#define FLASH (&g_flash_regs)
#define FLASH_ECCR_ECCD (1u << 31)
static uint8_t FL[3][2048];
static uint8_t *fpg(uint32_t a) { return a >= 0x0801E800u ? FL[2] + (a - 0x0801E800u) : a >= 0x0801E000u ? FL[0] + (a - 0x0801E000u) : FL[1] + (a - 0x0801D800u); }
static int ks_flash_erase_page(uint32_t a) { memset(fpg(a), 0xFF, 2048); return 0; }
static int ks_flash_program(uint32_t a, const uint8_t *d, size_t n) { uint8_t *p = fpg(a); for (size_t i = 0; i < n; i++) { if (p[i] != 0xFF) return -1; p[i] = d[i]; } return 0; }
#define em_f_map em_f_map_real
#include "ember_glue.inc"
#undef em_f_map
static const uint8_t *host_map(void *c, uint32_t a) { (void)c; return fpg(a); }
#include "extracted_ae_door.inc"      /* door_permits, now asking em_door_permits first */

/* ---- the ESP32 side ------------------------------------------------------- */
static int fails = 0, total = 0;
static void check(const char *n, int ok){ total++; if(!ok){ fails++; printf("FAIL %s\n", n);} }
static void esp_finish(void){ secure_wipe(g_ae_in,64); g_ae_in_valid=0; secure_wipe(g_ae_t,32); g_ae_t_valid=0; }
static int wreg(uint8_t reg, const uint8_t *p, size_t n) { return em_commit_write(reg, p, n); }
static int run(uint8_t cmd) { if (!door_permits(cmd)) return 999; do_em(cmd); esp_finish(); return (int8_t)g_em_out[0]; }
static uint16_t out_len(void) { return (uint16_t)(g_em_out[1] | (g_em_out[2] << 8)); }
static const uint8_t *out_p(void) { return g_em_out + 3; }
static void chunks(const uint8_t *d, size_t n) {
    for (size_t off = 0, i = 0; off < n; off += 64, i++) {
        uint8_t c[68] = {0}; c[0] = (uint8_t)n; c[1] = (uint8_t)(n >> 8); c[2] = (uint8_t)i; c[3] = (uint8_t)(i >> 8);
        memcpy(c + 4, d + off, n - off < 64 ? n - off : 64); wreg(G0_REG_EM_CHUNK, c, 68);
    }
}
static void dsha(const uint8_t *d, size_t n, uint8_t o[32]) { uint8_t t[32]; sha256(d, n, t); sha256(t, 32, o); }

/* simulated chain on easy params, as host_ember_e2e */
static const eh_params_t TPE = {
    .pow_limit = { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu },
    .interval = 2016, .timespan = 1209600, .no_retarget = 1,
};
#define BASE 800000u
static uint8_t HDR[8000][80]; static uint8_t BTX[8000][2][32]; static uint8_t BNT[8000]; static uint32_t NH;
static uint8_t MEMTX[1100]; static size_t MEML;
static void raw_txid(const uint8_t *r, uint8_t id[32]) {
    static uint8_t s[1100]; size_t k = 4, p = 6; memcpy(s, r, 4);
    uint8_t nin = r[p]; size_t a = p; p++; p += nin * 41u; uint8_t nout = r[p]; p++;
    for (int i = 0; i < nout; i++) { p += 8; p += 1 + r[p]; }
    memcpy(s + k, r + a, p - a); k += p - a;
    for (int i = 0; i < nin; i++) { uint8_t items = r[p++]; for (int j = 0; j < items; j++) p += 1 + r[p]; }
    memcpy(s + k, r + p, 4); k += 4; dsha(s, k, id);
}
static uint32_t mine(void) {
    uint32_t i = NH++; uint8_t *h = HDR[i];
    uint8_t cb[8]; memcpy(cb, &i, 4); memcpy(cb + 4, "cbcb", 4); dsha(cb, 8, BTX[i][0]); BNT[i] = 1;
    if (MEML) { raw_txid(MEMTX, BTX[i][1]); BNT[i] = 2; MEML = 0; }
    memset(h, 0, 80); h[0] = 4; if (i) dsha(HDR[i - 1], 80, h + 4);
    if (BNT[i] == 1) memcpy(h + 36, BTX[i][0], 32); else { uint8_t b[64]; memcpy(b, BTX[i][0], 32); memcpy(b + 32, BTX[i][1], 32); dsha(b, 64, h + 36); }
    uint32_t t = 1760000000u + i * 600u, bits = 0x207fffff; memcpy(h + 68, &t, 4); memcpy(h + 72, &bits, 4);
    for (uint32_t n = 0;; n++) { uint8_t hh[32]; memcpy(h + 76, &n, 4); dsha(h, 80, hh); if (!(hh[31] & 0x80)) break; }
    return BASE + i;
}
static int feed_last(void) { uint8_t in[81]; memcpy(in, HDR[NH - 1], 80); in[80] = 1; g_tick += 600000u; wreg(G0_REG_EM_HDR, in, 81); return run(G0_CMD_EM_HEADER); }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    g_ctx = secp256k1_context_preallocated_create(g_ctxbuf, SECP256K1_CONTEXT_NONE);
    memset(g_kg0, 0x5a, 32); memset(g_pool, 0x33, 32); for (int i = 0; i < 64; i++) SEED[i] = (uint8_t)(i * 3 + 1);
    memset(FL, 0xFF, sizeof FL);
    /* boot the core on the simulated chain (em_glue_boot would use mainnet + the compiled anchor) */
    mine();
    { em_env_t env = { g_ctx, { em_f_erase, em_f_prog, host_map, NULL }, em_ms, em_rand, em_leaf, NULL };
      eh_anchor_t a = {0}; a.height = BASE; dsha(HDR[0], 80, a.hash); a.bits = 0x207fffff; memcpy(&a.pstart, HDR[0] + 68, 4); a.ntimes = 1; a.times[0] = a.pstart;
      em_boot(&env, &TPE, &a); }
    em_glue_kat(); check("K: boot KAT (genesis id, retarget 32256, block 170 Merkle)", g_em_kat == 1);
    for (int i = 0; i < 30; i++) { mine(); check("W: header fed", feed_last() == EH_TIP); }
    check("K: KAT bit in EM_STATUS byte 95", out_p()[95] == 1);

    /* ── S ── EMBER_SAVE with no plan: a reboot keeps the clock */
    { em_env_t env = { g_ctx, { em_f_erase, em_f_prog, host_map, NULL }, em_ms, em_rand, em_leaf, NULL };
      eh_anchor_t a = {0}; a.height = BASE; dsha(HDR[0], 80, a.hash); a.bits = 0x207fffff; memcpy(&a.pstart, HDR[0] + 68, 4); a.ntimes = 1; a.times[0] = a.pstart;
      uint32_t tip = eh_tip_height(em_chain());
      check("S: SAVE", run(G0_CMD_EM_SAVE) == EM_OK);
      int e0 = 0; for (int p = 0; p < 2; p++) { (void)p; } (void)e0;
      check("S: SAVE again with no progress is a no-op", run(G0_CMD_EM_SAVE) == EM_OK);
      em_boot(&env, &TPE, &a);
      uint8_t s[EM_STATUS_LEN]; em_status(s);
      uint32_t fl = (uint32_t)s[40] | ((uint32_t)s[41] << 8) | ((uint32_t)s[42] << 16) | ((uint32_t)s[43] << 24);
      check("S: after reboot the clock restarts 6 below the saved tip", fl == tip - 6 && eh_tip_height(em_chain()) == tip - 6);
      for (uint32_t h = fl + 1; h <= tip; h++) { uint8_t in[81]; memcpy(in, HDR[h - BASE], 80); in[80] = 1; wreg(G0_REG_EM_HDR, in, 81); run(G0_CMD_EM_HEADER); }
      check("S: re-fed back to the tip", eh_tip_height(em_chain()) == tip); }

    /* ── R ── */
    uint8_t z[700] = {0};
    check("R: EM_HDR 80 dropped", (wreg(G0_REG_EM_HDR, z, 80), g_em_hdr_valid == 0));
    check("R: EM_HDR 82 dropped", (wreg(G0_REG_EM_HDR, z, 82), g_em_hdr_valid == 0));
    check("R: EM_SET 429 dropped", (wreg(G0_REG_EM_SET, z, 429), g_em_set_valid == 0));
    check("R: EM_SET 431 dropped", (wreg(G0_REG_EM_SET, z, 431), g_em_set_valid == 0));
    check("R: EM_ARG 63 dropped", (wreg(G0_REG_EM_ARG, z, 63), g_em_arg_valid == 0));
    check("R: EM_ARG 64 accepted", (wreg(G0_REG_EM_ARG, z, 64), g_em_arg_valid == 1));
    em_glue_wipe_inputs();
    { em_stage_reset(); uint8_t c[67] = {10, 0, 0, 0}; wreg(G0_REG_EM_CHUNK, c, 67); check("R: EM_CHUNK 67 dropped", em_stage_total() == 0); }
    check("R: unknown register ignored", wreg(0x2A, z, 5) == 0);
    check("R: header command with no EM_HDR refused", run(G0_CMD_EM_HEADER) == EM_E_LEN);

    /* ── D ── */
    static const uint8_t btc_only[] = { G0_CMD_EM_SET, G0_CMD_EM_CER_INIT, G0_CMD_EM_CER_FIN, G0_CMD_EM_COMMIT, G0_CMD_EM_CLEAR };
    static const uint8_t not_btc[]  = { G0_CMD_EM_RELEASE, G0_CMD_EM_PULSE, G0_CMD_EM_AWAY };
    static const uint8_t any[]      = { G0_CMD_EM_HEADER, G0_CMD_EM_PROOF, G0_CMD_EM_LIFE, G0_CMD_EM_STATUS, G0_CMD_EM_SAVE };
    for (int d = 0; d < 3; d++) { g_door = (uint8_t)d; int ok = 1;
        for (size_t i = 0; i < sizeof btc_only; i++) ok &= door_permits(btc_only[i]) == (d == DOOR_BTC);
        for (size_t i = 0; i < sizeof not_btc; i++)  ok &= door_permits(not_btc[i]) == (d != DOOR_BTC);
        for (size_t i = 0; i < sizeof any; i++)      ok &= door_permits(any[i]) == 1;
        check("D: door table", ok); }

    /* ── C ── ceremony in the BTC door */
    g_door = DOOR_BTC;
    uint8_t w[EP_SET_LEN] = {0};
    w[0] = 1; w[1] = 1; w[2] = 2;
    for (int i = 0; i < 32; i++) w[4 + i] = (uint8_t)(0x90 + i);
    w[4 + 36] = 0x80; w[4 + 37] = 0xF0; w[4 + 38] = 0xFA; w[4 + 39] = 0x02;            /* 0x02FAF080 = 50,000,000 sats */
    w[4 + 48] = 7;                                                                     /* m/84'/0'/0'/0/7 */
    w[160] = 0x00; w[161] = 0x14; memset(w + 162, 0x44, 20); w[194] = 0x10; w[195] = 0x27;   /* one heir, 10000 bp */
    w[376] = 0x00; w[377] = 0x14; memset(w + 378, 0x55, 20);
    w[410] = 0xC0; w[411] = 0x0F;                                                      /* quiet 4032 */
    w[414] = 30; w[418] = 5; w[420] = 20; w[422] = 80; w[424] = 10; w[426] = 0xE8; w[427] = 0x03;
    wreg(G0_REG_EM_SET, w, EP_SET_LEN);
    int b0 = burns;
    { int r = run(G0_CMD_EM_SET);
      check("C: EM_SET ok: 11 transactions, 11 signatures, v20 ceremony tip", r == EM_OK && out_len() == 6 && out_p()[0] == 3 + 2 * 4 && out_p()[1] == 11 &&
            (out_p()[2] | (out_p()[3] << 8) | ((uint32_t)out_p()[4] << 16) | ((uint32_t)out_p()[5] << 24)) == em_cer_tip0()); }
    static uint8_t UTX[16][600]; static size_t UTXL[16]; uint32_t peek_bad = 0;   /* v20: the unsigned transactions EM_CER_INIT showed */
    check("C: one seed fetch for the whole ceremony", burns == b0 + 1);
    static uint8_t BL[16][EM_BLOB_MAX]; static size_t BLL[16]; uint32_t nsig = 0, rel_bad = 0;
    for (;;) {
        uint8_t t[32], h[32], ae[64] = {0}; for (int i = 0; i < 32; i++) t[i] = (uint8_t)(nsig * 7 + i);
        ae_host_commit(AE_KIND_ECDSA, t, h); memcpy(ae + 32, h, 32); memcpy(g_ae_in, ae, 64); g_ae_in_valid = 1;
        int rc = run(G0_CMD_EM_CER_INIT); if (rc != EM_OK) break;
        uint16_t k = (uint16_t)(out_p()[0] | (out_p()[1] << 8)); uint8_t r0[33]; memcpy(r0, out_p() + 3, 33);
        { size_t tl = (size_t)(out_p()[68] | (out_p()[69] << 8)); uint8_t in = out_p()[2];   /* v20 */
          if (out_len() != 70 + tl || (in == 0) != (tl > 0) || tl > sizeof UTX[0] || (tl && out_p()[74] == 0x00)) peek_bad++;   /* first input only; no segwit marker = no witness */
          if (tl) { memcpy(UTX[k], out_p() + 70, tl); UTXL[k] = tl; } }
        memcpy(g_ae_t, t, 32); g_ae_t_valid = 1;
        if (run(G0_CMD_EM_CER_FIN) != EM_OK) { check("C: CER_FIN", 0); break; }
        if (!ae_host_check(g_ctx, AE_KIND_ECDSA, r0, t, out_p())) rel_bad++;
        size_t bl = (size_t)(out_p()[32] | (out_p()[33] << 8));
        if (bl) { memcpy(BL[k], out_p() + 34, bl); BLL[k] = bl; }
        nsig++;
    }
    check("C: every ceremony signature passes the host relation", nsig == 3 + 1 + 1 + 3 + 3 && rel_bad == 0);
    check("C: v20 EM_CER_INIT shows each unsigned transaction once, on its first input, never a witness", peek_bad == 0);
    { uint8_t ae[64] = {0}; memcpy(g_ae_in, ae, 64); g_ae_in_valid = 1; }   /* (the loop's last INIT was refused: all signed, ceremony kept) */
    check("C: EM_COMMIT", run(G0_CMD_EM_COMMIT) == EM_OK);
    check("C: account key gone after commit", g_em_acct_ok == 0);
    { uint8_t s[EM_STATUS_LEN]; em_status(s); check("C: plan live, link 0 of 2", (s[5] & 3) == 3 && s[6] == 0 && s[7] == 2); }
    /* wrong t aborts; idle timeout forgets the key (on a second, uncommitted ceremony) */
    { wreg(G0_REG_EM_SET, w, EP_SET_LEN); check("C2: EM_SET", run(G0_CMD_EM_SET) == EM_OK);
      uint8_t t[32] = {1}, h[32], ae[64] = {0}; ae_host_commit(AE_KIND_ECDSA, t, h); memcpy(ae + 32, h, 32);
      memcpy(g_ae_in, ae, 64); g_ae_in_valid = 1; check("C2: INIT", run(G0_CMD_EM_CER_INIT) == EM_OK);
      t[5] ^= 1; memcpy(g_ae_t, t, 32); g_ae_t_valid = 1;
      check("C2: FIN with a t that does not open h refused", run(G0_CMD_EM_CER_FIN) == EM_E_AE);
      check("C2: ceremony aborted, key wiped", g_em_acct_ok == 0);
      memcpy(g_ae_in, ae, 64); g_ae_in_valid = 1; check("C2: INIT after abort refused", run(G0_CMD_EM_CER_INIT) == EM_E_CEREMONY);
      wreg(G0_REG_EM_SET, w, EP_SET_LEN); run(G0_CMD_EM_SET);
      g_tick += EM_CER_TIMEOUT_MS + 1; em_glue_tick();
      check("C2: key forgotten after 2 min idle", g_em_acct_ok == 0);
      memcpy(g_ae_in, ae, 64); g_ae_in_valid = 1; check("C2: INIT after timeout refused", run(G0_CMD_EM_CER_INIT) == EM_E_CEREMONY);
      { uint8_t s[EM_STATUS_LEN]; em_status(s); check("C2: the committed plan is untouched", (s[5] & 3) == 3); } }

    /* ── N ── a Nostr life */
    g_door = DOOR_NOSTR; g_tier1_this_life = 0;
    { uint8_t a[64] = {0}; a[0] = 0x10; a[1] = 0x27; a[2] = 0x0C;   /* far future */
      wreg(G0_REG_EM_ARG, a, 64); check("N: AWAY before any tier-1 this life refused", run(G0_CMD_EM_AWAY) == EM_E_RULE); }
    { uint8_t sc[32]; fetch_scalar(sc); (void)true_pubkey_fill(sc); check("N: PUBKEY-style fetch caches the true key", g_true_pk_ok == 1); }
    fetch_scalar(z);   /* tier 1 with the key cached: binds the owner */
    { uint8_t s[EM_STATUS_LEN]; em_status(s); check("N: owner bound by the G0 itself", s[5] & 4); }
    { uint8_t t[32], h[32], ae[64] = {0}; for (int i = 0; i < 32; i++) t[i] = (uint8_t)(200 - i);
      ae_host_commit(AE_KIND_SCHNORR, t, h); memcpy(ae + 32, h, 32); memcpy(g_ae_in, ae, 64); g_ae_in_valid = 1;
      check("N: EM_PULSE", run(G0_CMD_EM_PULSE) == EM_OK);
      uint8_t r0[33], ser[256]; memcpy(r0, out_p(), 33); size_t sl = (size_t)(out_p()[33] | (out_p()[34] << 8)); memcpy(ser, out_p() + 35, sl);
      memcpy(g_ae_t, t, 32); g_ae_t_valid = 1;
      check("N: AE_FINISH signs the Pulse", do_ae_finish() == 0); esp_finish();
      uint8_t sig[64]; memcpy(sig, g_sig_out, 64);
      check("N: host relation on the Pulse signature", ae_host_check(g_ctx, AE_KIND_SCHNORR, r0, t, sig));
      uint8_t id[32]; sha256(ser, sl, id);
      secp256k1_xonly_pubkey pk; secp256k1_keypair kp; secp256k1_keypair_create(g_ctx, &kp, SK); secp256k1_keypair_xonly_pub(g_ctx, &pk, NULL, &kp);
      check("N: BIP-340 verify over the event id", secp256k1_schnorrsig_verify(g_ctx, sig, id, 32, &pk));
      chunks(ser, sl); wreg(G0_REG_EM_ARG, sig, 64);
      check("N: the signed Pulse is accepted back as life", run(G0_CMD_EM_LIFE) == EM_OK);
      chunks(ser, sl); sig[9] ^= 1; wreg(G0_REG_EM_ARG, sig, 64);
      check("N: a flipped signature is refused", run(G0_CMD_EM_LIFE) == EL_E_SIG); }
    { uint8_t a[64] = {0}; uint32_t h = BASE + 40000; memcpy(a, &h, 4); a[40] = 1;
      wreg(G0_REG_EM_ARG, a, 64); check("N: AWAY with a non-zero tail refused", run(G0_CMD_EM_AWAY) == EM_E_LEN);
      a[40] = 0; wreg(G0_REG_EM_ARG, a, 64); check("N: AWAY accepted after tier 1", run(G0_CMD_EM_AWAY) == EM_OK); }

    /* ── W ── walk to the R1 window through the registers, release, mine, prove */
    int released = 0; uint8_t txid[32]; uint32_t mined_at = 0;
    for (int i = 0; i < 6000 && !(mined_at && NH - 1 >= mined_at - BASE + 2); i++) {
        mine(); int fr = feed_last();
        if (fr != EH_TIP) { check("W: header fed", 0); break; }
        if (!released && g_em_out[3 + 44] == 1) {
            uint8_t s[EM_STATUS_LEN]; memcpy(s, out_p(), EM_STATUS_LEN);
            uint32_t k = em_blob_index((ew_release_t){ s[44], s[45], s[46] });
            g_door = DOOR_BTC; chunks(BL[k], BLL[k]); check("W: RELEASE refused in the BTC door", run(G0_CMD_EM_RELEASE) == 999);
            g_door = DOOR_NOSTR; chunks(BL[k], BLL[k]);
            check("W: RELEASE of R1 in its window", run(G0_CMD_EM_RELEASE) == EM_OK);
            memcpy(MEMTX, out_p(), out_len()); MEML = out_len(); raw_txid(MEMTX, txid); released = 1;
            { uint8_t u[32]; dsha(UTX[k], UTXL[k], u);   /* v20: the released transaction is the one checked at the ceremony */
              check("W: v20 released R1 has the txid of the unsigned transaction shown at the ceremony", UTXL[k] && !memcmp(u, txid, 32)); }
        } else if (released && !mined_at && BNT[NH - 1] == 2) mined_at = BASE + NH - 1;
    }
    check("W: R1 released and mined", released && mined_at);
    { uint8_t p[EM_PROOF_LEN] = {0}; uint32_t i = mined_at - BASE;
      p[0] = 'R'; p[1] = 1; p[3] = 1; p[4] = 1; memcpy(p + 8, HDR[i], 80); memcpy(p + 88, BTX[i][0], 32);
      chunks(p, sizeof p); check("W: EM_PROOF of R1, 3 deep", run(G0_CMD_EM_PROOF) == EM_OK);
      uint8_t s[EM_STATUS_LEN]; em_status(s); check("W: link 1", s[6] == 1);
      chunks(p, sizeof p); check("W: the same proof again changes nothing", run(G0_CMD_EM_PROOF) == EM_E_RULE); }

    /* ── F ── every slot at random and wrong lengths, random commands in random doors */
    { uint64_t r = 0x51075107ULL; uint8_t buf[600]; long ops = 0, rel_ok = 0, proof_ok = 0, set_ok = 0;
      uint32_t link0 = em_walk()->link;
      #define RN() (r ^= r << 13, r ^= r >> 7, r ^= r << 17, (uint32_t)r)
      static const uint8_t regs[] = { G0_REG_EM_HDR, G0_REG_EM_SET, G0_REG_EM_CHUNK, G0_REG_EM_ARG, G0_REG_EM_OUT, 0x1A, 0x19 };
      for (long it = 0; it < 200000; it++) {
          uint32_t k = RN() % 100;
          if (k < 60) {
              uint8_t reg = regs[RN() % sizeof regs]; size_t n;
              uint32_t m = RN() % 4;   /* exact length, off by one, or anything */
              size_t exact = reg == G0_REG_EM_HDR ? 81 : reg == G0_REG_EM_SET ? 430 : reg == G0_REG_EM_CHUNK ? 68 : 64;
              n = m == 0 ? exact : m == 1 ? exact + 1 : m == 2 ? exact - 1 : RN() % 515;
              for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)RN();
              if (reg == G0_REG_EM_CHUNK && n == 68 && (RN() & 1)) { buf[0] = (uint8_t)(RN() % 2100); buf[1] = (uint8_t)(RN() % 9); buf[2] = (uint8_t)(RN() % 40); buf[3] = 0; }
              if (reg == 0x19 && n == 64) { memcpy(g_ae_in, buf, 64); g_ae_in_valid = 1; }
              else if (reg == 0x1A && n == 32) { memcpy(g_ae_t, buf, 32); g_ae_t_valid = 1; }
              else wreg(reg, buf, n);
          } else {
              uint8_t cmd = (uint8_t)(G0_CMD_EM_HEADER + RN() % 13);
              if (cmd == G0_CMD_EM_CLEAR) continue;            /* keep the plan for the invariants */
              g_door = (uint8_t)(RN() % 3);
              int rc = run(cmd); ops++;
              if (cmd == G0_CMD_EM_RELEASE && rc == EM_OK) rel_ok++;
              if (cmd == G0_CMD_EM_PROOF && rc == EM_OK) proof_ok++;
              if (cmd == G0_CMD_EM_SET && rc == EM_OK) set_ok++;
              if (cmd == G0_CMD_EM_COMMIT && rc == EM_OK) { check("F: a random COMMIT succeeded", 0); break; }
              if (cmd == G0_CMD_EM_PULSE && rc == EM_OK) { ae_wipe(); }
          }
      }
      check("F: no random blob ever released", rel_ok == 0);
      check("F: no random proof ever accepted", proof_ok == 0);
      check("F: the walk did not move", em_walk()->link == link0);
      { uint8_t st[EM_STATUS_LEN]; em_status(st); check("F: plan intact", (st[5] & 3) == 3); }
      em_glue_abort();
      printf("  fuzz: 200000 random register writes and commands (%ld commands, %ld random EMBER_SETs validated): nothing released, nothing proved\n", ops, set_ok); }

    /* ── X ── */
    g_door = DOOR_NOSTR; check("X: CLEAR refused outside the BTC door", run(G0_CMD_EM_CLEAR) == 999);
    g_door = DOOR_BTC;   check("X: CLEAR", run(G0_CMD_EM_CLEAR) == EM_OK);
    { uint8_t s[EM_STATUS_LEN]; em_status(s); check("X: no plan", (s[5] & 1) == 0); }

    printf("ember glue: %d/%d passed\n", total - fails, total);
    return fails != 0;
}
