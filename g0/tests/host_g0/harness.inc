/* ===========================================================================
 * Host harness for the REAL G0 firmware (audit 21 Nov 2026). Included at the
 * end of the transformed g0/src/main.c, so it sees every static. The test
 * plays the ESP32: honest onboarding and honest lives, plus an attacker that
 * owns the ESP32 in radio lives. The SE is fakese.c.
 * ======================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "fakese.h"

I2C_TypeDef fake_i2c1; GPIO_TypeDef fake_gpioa, fake_gpiob; TAMP_TypeDef fake_tamp; RCC_TypeDef fake_rcc;
FLASH_TypeDef fake_flash_regs; SysTick_Type fake_systick; SCB_Type fake_scb; RNG_TypeDef fake_rng; MPU_Type fake_mpu;
static uint32_t h_tick = 1000;
uint32_t HAL_GetTick(void) { return h_tick++; }
void HAL_IncTick(void) { h_tick++; }
static uint8_t *h_flash;
HAL_StatusTypeDef HAL_FLASH_Unlock(void) { return HAL_OK; }
HAL_StatusTypeDef HAL_FLASH_Lock(void) { return HAL_OK; }
HAL_StatusTypeDef HAL_FLASH_Program(uint32_t type, uint32_t addr, uint64_t data) {
    (void)type; if (addr < FLASH_BASE || addr + 8 > FLASH_BASE + 0x20000) return HAL_ERROR;
    memcpy(h_flash + (addr - FLASH_BASE), &data, 8); return HAL_OK;
}
HAL_StatusTypeDef HAL_FLASHEx_Erase(FLASH_EraseInitTypeDef *e, uint32_t *err) {
    uint32_t base = (e->Banks == FLASH_BANK_2 ? FLASH_BANK_SIZE : 0) + e->Page * FLASH_PAGE_SIZE;
    uint32_t n = e->NbPages ? e->NbPages : 1;
    if (base + n * FLASH_PAGE_SIZE > 0x20000) return HAL_ERROR;
    memset(h_flash + base, 0xFF, n * FLASH_PAGE_SIZE); *err = 0xFFFFFFFFu; return HAL_OK;
}
static void h_flash_init(void) {
    h_flash = mmap((void *)FLASH_BASE, 0x20000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (h_flash != (uint8_t *)FLASH_BASE) { perror("mmap flash"); exit(2); }
    memset(h_flash, 0xFF, 0x20000);
}

/* ---- the bus, as the ESP32 sees it ---- */
static void hw(uint8_t reg, const uint8_t *p, size_t n) {
    uint8_t b[600]; b[0] = reg; if (n) memcpy(b + 1, p, n); host_write(b, n + 1);
}
static int hcmd(uint8_t cmd) {     /* send a command, run it; returns the status after */
    uint8_t c = cmd; hw(G0_REG_CMD, &c, 1);
    if (cmd == G0_CMD_RESET) { g0_step(); return g_status; }
    if (!g_cmd_pending) return -1;   /* not accepted */
    g0_step();
    return g_status;
}
static void hreset(void) { hcmd(G0_CMD_RESET); }

/* ---- object ids for a generation ---- */
#define ID(base, g) ((uint32_t)(base) + ((uint32_t)(g) << 8))
static uint32_t PIN_D(int g) { return ID(0x70000003u, g); }
static uint32_t PIN_S(int g) { return ID(0x70000005u, g); }
static uint32_t PIN_P(int g) { return ID(0x70000007u, g); }
static uint32_t O_MODE(int g) { return ID(0x20000033u, g); }
static uint32_t O_G0(int g) { return ID(0x20000030u, g); }
static uint32_t O_REC(int g) { return ID(0x20000035u, g); }
static uint32_t O_SEEDK(int g) { return ID(0x20000020u, g); }
static uint32_t O_DAILYK(int g) { return ID(0x20000022u, g); }
static uint32_t O_SCALAR(int g) { return ID(0x20000002u, g); }
static uint32_t O_PCRU(int g) { return ID(0x20000031u, g); }
static uint32_t O_D1S(int g) { return ID(0x20000036u, g); }

static void pol(fse_obj_t *o, uint32_t who, uint32_t r) { fse_pol_t *e = &o->pol[o->npol++]; memset(e, 0, sizeof *e); e->who = who; e->rights = r; }
static void polg(fse_obj_t *o, uint32_t who, uint32_t r, uint32_t pcr, const uint8_t v[32]) { fse_pol_t *e = &o->pol[o->npol++]; memset(e, 0, sizeof *e); e->who = who; e->rights = r; e->gate_pcr = pcr; memcpy(e->gate_val, v, 32); }

/* ---- what one wallet is ---- */
typedef struct {
    int gen; uint8_t kse[16], kg0[32], S[32], seed[64], scalar[32]; char dpin[8], spin[8], ppin[8];
    uint8_t mfp[4];   /* fingerprint the G0 reported at the first BTC life */
} wallet_t;
static void consts(uint8_t nostrc[32], uint8_t armc[32]) {
    memset(nostrc, 0, 32); memcpy(nostrc, "FAVILLA-MODE-NOSTR", 18);
    memset(armc, 0, 32); memcpy(armc, "FAVILLA-MODE-ARM", 16);
}
static void btc_value(const uint8_t S[32], uint8_t out[32]) { uint8_t n[32]; fse_neutral(n); fse_ext(n, S, out); }
static void krec(const uint8_t kse[16], uint8_t out[16]) {
    static const uint8_t label[] = "favilla-recover-key";
    uint8_t h[32]; sha256_ctx c; sha256_init(&c); sha256_update(&c, kse, 16); sha256_update(&c, label, sizeof(label) - 1); sha256_final(&c, h);
    memcpy(out, h, 16);
}
/* a PIN session op by the ESP32: principal = the PIN object, PIN checked */
static int pin_ok(uint32_t pinobj, const char *pin) { fse_obj_t *p = fse_find(pinobj); return p && p->kind == FSE_K_PIN && strcmp((char *)p->val, pin) == 0; }
static int pin_extend(uint32_t pinobj, const char *pin, uint32_t pcr, const uint8_t e[32]) {
    if (!pin_ok(pinobj, pin)) return 0;
    fse_obj_t *o = fse_find(pcr); if (!o || o->kind != FSE_K_PCR) return 0;
    if (!(fse_rights(o, pinobj) & FSE_R_WRITE)) return 0;
    fse_ext(o->val, e, o->val); return 1;
}
static int pin_read(uint32_t pinobj, const char *pin, uint32_t pcr, uint8_t out[32]) {
    if (!pin_ok(pinobj, pin)) return 0;
    fse_obj_t *o = fse_find(pcr); if (!o || !(fse_rights(o, pinobj) & FSE_R_READ)) return 0;
    memcpy(out, o->val, 32); return 1;
}

/* ---- G0 boot: a real power cycle (PWRRSTF) or a non-power reset ---- */
static void g0_power_on(int power) {
    /* RAM statics keep their values on a host; a real boot starts them at
     * zero. Clear the ones a fresh boot would clear: everything not in flash
     * or the backup domain. The simplest faithful way: the harness keeps no
     * G0 RAM across a boot except what main() itself sets, so zero the
     * key/door state main() relies on. */
    g_door = DOOR_UNSET; g_keys_valid = 0; g_seal_window = 0; g_recover_gone = 0; g_door1_locked = 0;
    g_pend_valid = 0; g_pass_valid = 0; g_true_pk_ok = 0; g_ae.kind = AE_KIND_NONE;
    g_cmd_pending = 0; g_reset_pending = 0; g_status = G0_ST_IDLE;
    g_seed_in_valid = g_keys_in_valid = g_store_in_valid = g_hash_in_valid = g_btc_in_valid = g_ae_in_valid = g_ae_t_valid = g_ent_in_valid = 0;
    g_life_resumed = 0; g_wiped_life = 0; g_lbl_used = 0; g_imp_used = 0;   /* .bss on a real boot; life_restore() refills from BKP1R */
    /* Every RAM static that life_restore() refills must be cleared here, or a
     * host "power-on" keeps the last life's value where a real boot has its
     * initial one. main() re-arms the one-shots and the passphrase budget itself
     * each boot; g_vlt_refills it never sets, so without this line the refill
     * count carried across a power cycle (24 Nov 2026). */
    g_mode_reset_arm = 0; g_mode_btc_arm = 0; g_mode_pk_arm = 0; g_pass_budget = 0; g_vlt_refills = 0;
    fake_rcc.CSR = power ? RCC_CSR_PWRRSTF : RCC_CSR_PINRSTF;
    if (power) { fake_tamp.BKP0R = 0; fake_tamp.BKP1R = 0; }   /* VDD gone: backup domain gone too (no VBAT) */
    int st = g0_boot();
    host_set_selftest(st);
    if (st != 0) { printf("G0 self-test failed (%d)\n", st); exit(3); }
}

/* ---- honest onboarding (the ESP32's order, roughly se_signer.cpp) ---- */
static int onboard_x(wallet_t *w, int attacker) {
    int g = w->gen; uint8_t nostrc[32], armc[32], tmp[32], btcv[32], nostrv[32], n[32];
    consts(nostrc, armc); fse_neutral(n);
    fse_obj_t *o;
    o = fse_create(O_REC(g), FSE_K_AUTH); if (!o) return -20; krec(w->kse, o->val); pol(o, O_REC(g), FSE_R_DELETE);
    o = fse_create(PIN_D(g), FSE_K_PIN); if (!o) return -20; strcpy((char *)o->val, w->dpin); pol(o, PIN_D(g), FSE_R_READ | FSE_R_WRITE | FSE_R_DELETE);
    o = fse_create(PIN_S(g), FSE_K_PIN); if (!o) return -20; strcpy((char *)o->val, w->spin); pol(o, PIN_S(g), FSE_R_READ | FSE_R_WRITE | FSE_R_DELETE);
    o = fse_create(PIN_P(g), FSE_K_PIN); if (!o) return -20; strcpy((char *)o->val, w->ppin); pol(o, PIN_P(g), FSE_R_READ | FSE_R_WRITE | FSE_R_DELETE);
    o = fse_create(O_MODE(g), FSE_K_PCR); if (!o) return -20; sha256((const uint8_t *)"created", 7, o->val);   /* a fresh PCR is not at the reset base */
    pol(o, PIN_D(g), FSE_R_READ | FSE_R_WRITE); pol(o, PIN_S(g), FSE_R_READ | FSE_R_WRITE); pol(o, PIN_P(g), FSE_R_READ | FSE_R_WRITE);
    pol(o, O_G0(g), FSE_R_READ | FSE_R_WRITE | FSE_R_DELETE); pol(o, O_REC(g), FSE_R_DELETE);
    /* G0 keys */
    uint8_t k[KEYS_LEN]; memcpy(k, w->kse, 16); memcpy(k + 16, w->kg0, 32); memcpy(k + 48, w->S, 32); k[80] = (uint8_t)g;
    hreset(); hw(G0_REG_KEYS_IN, k, KEYS_LEN); if (hcmd(G0_CMD_SETKEYS) != G0_ST_SIG_READY) { printf("  onboard: SETKEYS refused\n"); return -2; }
    o = fse_create(O_G0(g), FSE_K_AUTH); if (!o) return -20; memcpy(o->val, w->kse, 16); pol(o, O_REC(g), FSE_R_DELETE);
    o = fse_create(O_PCRU(g), FSE_K_PCR); if (!o) return -20; fse_neutral(o->val); pol(o, O_G0(g), FSE_R_WRITE);
    o = fse_create(O_D1S(g), FSE_K_BIN); if (!o) return -20; o->len = 48; pol(o, PIN_D(g), FSE_R_READ); pol(o, O_REC(g), FSE_R_DELETE);
    /* the latch to NEUTRAL by the G0's one-shot, then NOSTR by the daily PIN */
    hreset(); hcmd(G0_CMD_MODERESET);
    if (g_sig_out[5] != 0 && !attacker) { printf("  onboard: MODERESET step %u\n", g_sig_out[5]); return -3; }
    if (g_sig_out[5] == 0 && !pin_extend(PIN_D(g), w->dpin, O_MODE(g), nostrc)) return -4;
    fse_ext(n, nostrc, nostrv); btc_value(w->S, btcv);
    o = fse_create(O_DAILYK(g), FSE_K_AES); if (!o) return -20; for (int i = 0; i < 32; i++) o->val[i] = (uint8_t)(0x50 + i + g);
    pol(o, PIN_D(g), FSE_R_ENC | FSE_R_DEC | FSE_R_DELETE); polg(o, O_G0(g), FSE_R_DEC, O_MODE(g), nostrv); pol(o, O_REC(g), FSE_R_DELETE);
    /* Nostr scalar: G0 inner seal, SE outer layer */
    hreset(); hw(G0_REG_HASH_IN, w->scalar, 32); if (hcmd(G0_CMD_PROVISION) != G0_ST_SIG_READY) return -5;
    uint8_t inner32[32], iv[16]; memcpy(inner32, g_sig_out, 32); for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(0xA0 + i);
    o = fse_create(O_SCALAR(g), FSE_K_BIN); if (!o) return -20; o->len = 48; memcpy(o->val, iv, 16);
    fse_crypt(fse_find(O_DAILYK(g)), inner32, iv, o->val + 16);
    pol(o, PIN_D(g), FSE_R_READ | FSE_R_WRITE | FSE_R_DELETE); pol(o, O_G0(g), FSE_R_READ); pol(o, O_REC(g), FSE_R_DELETE);
    /* seed: G0 inner seal, SE outer layer under the seed wrap key, the blob back to the G0 */
    o = fse_create(O_SEEDK(g), FSE_K_AES); if (!o) return -20; for (int i = 0; i < 32; i++) o->val[i] = (uint8_t)(0x90 + i + g);
    pol(o, PIN_D(g), FSE_R_ENC | FSE_R_WRITE | FSE_R_DELETE); polg(o, PIN_S(g), FSE_R_DEC, O_MODE(g), btcv); pol(o, O_REC(g), FSE_R_DELETE);
    uint8_t sin[96] = {0}; memcpy(sin, w->seed, 64);
    hreset(); hw(G0_REG_SEED_IN, sin, 96); if (hcmd(G0_CMD_SEEDSEAL) != G0_ST_SIG_READY) { printf("  onboard: SEEDSEAL refused\n"); return -6; }
    uint8_t inner[64]; memcpy(inner, g_sig_out, 64);
    uint8_t st[97]; st[0] = SS_KIND_SEED;
    for (int i = 0; i < 16; i++) { st[1 + i] = (uint8_t)(0xB0 + i); st[1 + 48 + i] = (uint8_t)(0xC0 + i); }
    fse_obj_t *sk = fse_find(O_SEEDK(g));
    fse_crypt(sk, inner, st + 1, st + 1 + 16); fse_crypt(sk, inner + 32, st + 1 + 48, st + 1 + 64);
    hreset(); hw(G0_REG_STORE_IN, st, 97); hcmd(G0_CMD_SEEDSTORE);
    if (g_sig_out[5] != 0) { printf("  onboard: SEEDSTORE rc %02X\n", g_sig_out[5]); return -7; }
    (void)tmp;
    return 0;
}

static int onboard(wallet_t *w) { return onboard_x(w, 0); }
/* ---- an honest life ---- */
static int life_nostr(wallet_t *w) {   /* boot (fresh), door NOSTR, daily PIN, one Nostr op */
    uint8_t nostrc[32], armc[32]; consts(nostrc, armc);
    hreset(); hcmd(G0_CMD_DOOR1LOCK);
    hreset(); hcmd(G0_CMD_MODERESET);
    hreset(); hcmd(G0_CMD_DOORNOSTR);
    if (g_door != DOOR_NOSTR) return -1;
    if (!pin_extend(PIN_D(w->gen), w->dpin, O_MODE(w->gen), nostrc)) return -2;
    hreset(); int st = hcmd(G0_CMD_PUBKEY);
    return st == G0_ST_SIG_READY ? 0 : -3;
}
/* the BTC door as btcWitnessedSpendOpen + DOORKEYS; returns 0 and the fingerprint */
static int g_inner_known = 0; static uint8_t g_inner_pkt[96];   /* what an ESP32 in this life saw */
static int btc_unlock_and_keys(int gen, const char *spin, uint8_t mfp[4], int verbose) {
    uint8_t nostrc[32], armc[32]; consts(nostrc, armc);
    if (!pin_ok(PIN_S(gen), spin)) { if (verbose) printf("  btc: spend PIN refused\n"); return -1; }
    if (!pin_extend(PIN_S(gen), spin, O_MODE(gen), armc)) { if (verbose) printf("  btc: arm refused\n"); return -2; }
    hreset(); hcmd(G0_CMD_MODEBTC);
    if (g_sig_out[5] != 0) { if (verbose) printf("  btc: MODEBTC diag %02X class %u\n", g_sig_out[5], g_sig_out[20]); return -3; }
    /* SEEDGET, then the SE strips its layer in the spend session */
    hreset(); hcmd(G0_CMD_SEEDGET);
    if (g_btc_out[5] != 0) { if (verbose) printf("  btc: SEEDGET rc %02X\n", g_btc_out[5]); return -4; }
    uint8_t outer[96]; memcpy(outer, g_btc_out + 8, 96);
    uint8_t inner[64];
    if (fse_cipher(PIN_S(gen), O_SEEDK(gen), 1, outer + 16, outer, inner) != 0x9000 ||
        fse_cipher(PIN_S(gen), O_SEEDK(gen), 1, outer + 64, outer + 48, inner + 32) != 0x9000) { if (verbose) printf("  btc: SE refused DEC\n"); return -5; }
    uint8_t pkt[96] = {0}; memcpy(pkt, inner, 64); memcpy(pkt + 64, INNER_PKT_MAGIC, 4);
    memcpy(g_inner_pkt, pkt, 96); g_inner_known = 1;
    hreset(); hw(G0_REG_SEED_IN, pkt, 96); hcmd(G0_CMD_DOORKEYS);
    if (g_btc_out[5] != 0) { if (verbose) printf("  btc: DOORKEYS rc %02X\n", g_btc_out[5]); return -6; }
    memcpy(mfp, g_btc_out + 6, 4);
    return 0;
}
static int life_btc(wallet_t *w, uint8_t mfp[4], int verbose) {
    hreset(); hcmd(G0_CMD_DOOR1LOCK);
    hreset(); hcmd(G0_CMD_MODERESET);
    hreset(); hcmd(G0_CMD_DOORBTC);
    if (g_door != DOOR_BTC) return -10;
    return btc_unlock_and_keys(w->gen, w->spin, mfp, verbose);
}
static int life_vault(wallet_t *w) {   /* VAULT (passkey) life: Bluetooth, the passkey PIN typed */
    uint8_t nostrc[32], armc[32]; consts(nostrc, armc);
    hreset(); hcmd(G0_CMD_DOOR1LOCK);
    hreset(); hcmd(G0_CMD_MODERESET);
    hreset(); hcmd(G0_CMD_DOORPASSKEY);
    if (g_door != DOOR_PASSKEY) return -1;
    if (!pin_extend(PIN_P(w->gen), w->ppin, O_MODE(w->gen), armc)) return -2;   /* the passkey door arms like the others */
    hreset(); hcmd(G0_CMD_MODEDOOR);
    return g_sig_out[5] == 0 ? 0 : -3;
}
static void wallet_make(wallet_t *w, int gen, uint8_t salt) {
    memset(w, 0, sizeof *w); w->gen = gen;
    for (int i = 0; i < 16; i++) w->kse[i] = (uint8_t)(salt + i);
    for (int i = 0; i < 32; i++) { w->kg0[i] = (uint8_t)(salt * 3 + i); w->S[i] = (uint8_t)(salt * 5 + i); w->scalar[i] = (uint8_t)(salt * 7 + i + 1); }
    for (int i = 0; i < 64; i++) w->seed[i] = (uint8_t)(salt * 11 + i);
    snprintf(w->dpin, 8, "%06u", 100000u + salt); snprintf(w->spin, 8, "%06u", 200000u + salt); snprintf(w->ppin, 8, "%06u", 300000u + salt);
}
