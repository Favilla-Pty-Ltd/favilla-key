/* Host test for the 19 Oct 2026 fixes (review findings 3 and 4).
 * Runs the REAL do_wipeall / wipe_order / do_door / door_permits /
 * door_autocommit source, extracted from src/main.c, against a fake SE that
 * tracks object existence and deletes. The fake SE also models the attack:
 * a deleted MODE_PCR id can be re-created at any initial value, and the seed
 * wrap key's spend-PIN DEC only checks "MODE_PCR exists and reads BTC". */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "scp03.h"
#include "se_objects.h"
#define G0_CMD_SIGN 0x01
#define G0_CMD_PROVISION 0x03
#define G0_CMD_ECDH 0x04
#define G0_CMD_PUBKEY 0x05
#define G0_CMD_CACHEKEY 0x06
#define G0_CMD_SESSIONTEST 0x09
#define G0_CMD_MODEBTC 0x0B
#define G0_CMD_DOORKEYS 0x0E
#define G0_CMD_BTCSIGN 0x0F
#define G0_CMD_MSGSIGN 0x1B
#define G0_CMD_SIGN_INIT 0x1C      /* 27 Oct 2026: anti-exfil ids */
#define G0_CMD_AE_FINISH 0x1D
#define G0_CMD_BTCSIGN_INIT 0x1E
#define G0_CMD_MSGSIGN_INIT 0x1F
#define G0_CMD_MODEDOOR 0x21       /* 30 Oct 2026: generic doors */
#define G0_CMD_PKSIGN 0x22   /* restorable passkeys, 30 Oct 2026 */
#define G0_CMD_VSIGN_INIT 0x29   /* v14 vault backup signature */
#define G0_CMD_VAULT 0x28    /* vault records, 2 Nov 2026 */
static uint8_t g_pk_scratch_own;   /* restorable passkeys: do_wipeall clears it */
#define AE_KIND_NONE 0
#define AE_KIND_SCHNORR 1
static struct { uint8_t kind; } g_ae;
#define DOOR_UNSET 0
#define DOOR_NOSTR 1
#define DOOR_BTC 2
#define DOOR_PASSKEY 3
uint32_t g_gen_off = 0x300;
static int g_keys_valid = 1, g_recover_gone = 0, g_seal_window = 0, life_saves = 0;
static uint8_t g_door = DOOR_UNSET, g_sesdiag[64], g_sig_out[64];
static void life_save(void) { life_saves++; }
static void secure_wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }
static void host_challenge(uint8_t hc[8]) { memset(hc, 0x11, 8); }
static void entropy_mix(const uint8_t *p, size_t n) { (void)p; (void)n; }
static void krecover_key(uint8_t k[16]) { memset(k, 0x33, 16); }
static int relay_xfer(void *c, const uint8_t *a, size_t al, uint8_t *r, size_t rc, size_t *rl) { (void)c;(void)a;(void)al;(void)r;(void)rc;(void)rl; return -1; }

/* ── fake SE ── */
enum { O_SCALAR, O_NSEC, O_WDAILY, O_WSEED, O_PAIR, O_D1SEC, O_MODE, O_G0AUTH, O_RECOVER, O_N };
static int se_exists[O_N], se_refuse[O_N], n_deletes;
static int relay_drops_at = -1;            /* the relay skips this delete and forges "absent" */
static int session_broken = 0;
static uint8_t SE_MODE[32], BTC_VALUE[32];
static int obj_index(uint32_t oid) {
    if (oid == SE_OBJ_NOSTR_SCALAR)   return O_SCALAR;
    if (oid == SE_OBJ_NSEC_IMPORT)    return O_NSEC;
    if (oid == SE_OBJ_AES_WRAP_DAILY) return O_WDAILY;
    if (oid == SE_OBJ_AES_WRAP_SEED)  return O_WSEED;
    if (oid == SE_OBJ_PAIR_WRAP)      return O_PAIR;
    if (oid == SE_OBJ_DOOR1_SECRET)   return O_D1SEC;
    if (oid == SE_OBJ_PCR_MODE)       return O_MODE;
    if (oid == SE_AUTH_OBJ_G0)        return O_G0AUTH;
    if (oid == SE_AUTH_OBJ_RECOVER)   return O_RECOVER;
    return -1; }
int scp03_open(scp03_session_t *s, scp03_xfer_fn x, void *xc, const uint8_t k[16], uint32_t auth, const uint8_t h[8], uint8_t cc[8]) {
    (void)x;(void)xc;(void)k;(void)h; memset(s, 0, sizeof(*s)); if (cc) memset(cc, 0x22, 8);
    session_broken = 0;
    if (auth == SE_AUTH_OBJ_RECOVER && !se_exists[O_RECOVER]) { s->stage = 1; return -1; }
    s->stage = 4; s->authed = 1; return 0; }
int scp03_cmd(scp03_session_t *s, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *d, size_t dl, int hasle, uint8_t *o, size_t oc, size_t *ol) {
    (void)p1;(void)hasle;(void)o;(void)oc;(void)ol; s->nxfer++;
    uint32_t oid = dl >= 6 ? ((uint32_t)d[2] << 24 | (uint32_t)d[3] << 16 | (uint32_t)d[4] << 8 | d[5]) : 0;
    int i = obj_index(oid);
    if (ins == 0x04 && p2 == 0x28 && i >= 0) {
        if (i == relay_drops_at) { session_broken = 1; s->last_sw = 0x6A88; return -1; }   /* never reached the SE */
        if (session_broken) { s->last_sw = 0x6982; return -1; }   /* SE: C-MAC chain mismatch */
        n_deletes++;
        if (!se_exists[i]) { s->last_sw = 0x6985; return -1; }
        if (se_refuse[i])  { s->last_sw = 0x6986; return -1; }
        se_exists[i] = 0; s->last_sw = 0x9000; return 0; }
    s->last_sw = 0x6985; return -1; }
int scp03_close(scp03_session_t *s) { memset(s, 0, sizeof(*s)); return 0; }
void scp03_wipe(scp03_session_t *s) { memset(s, 0, sizeof(*s)); }

/* The attack, as the SE would see it after any delete of MODE_PCR: re-create
 * the id at the public BTC value, then ask for spend-PIN DEC of the seed key. */
static int attacker_gets_seed_dec(void) {
    if (se_exists[O_MODE]) return 0;            /* cannot re-create a live object */
    se_exists[O_MODE] = 1; memcpy(SE_MODE, BTC_VALUE, 32);
    return se_exists[O_WSEED] && memcmp(SE_MODE, BTC_VALUE, 32) == 0;
}
static void se_full(void) { for (int i = 0; i < O_N; i++) { se_exists[i] = 1; se_refuse[i] = 0; } relay_drops_at = -1; n_deletes = 0; }

/* 28 Oct 2026: Emberwill ids referenced by the extracted door code (ember_glue.inc) */
#define G0_CMD_EM_PULSE 0x39
static int em_door_permits(uint8_t c) { (void)c; return -1; }
#include "extracted34.inc"

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("PASS  %s\n", m); else { printf("FAIL  %s\n", m); fails++; } } while (0)

int main(void) {
    memset(BTC_VALUE, 0xB7, 32);

    /* finding 4: door auto-commit */
    g_door = DOOR_UNSET; door_autocommit(G0_CMD_PROVISION);
    CHECK(g_door == DOOR_UNSET, "PROVISION in an unset life does not commit a door (onboarding untouched)");
    door_autocommit(G0_CMD_PUBKEY);
    CHECK(g_door == DOOR_NOSTR && life_saves == 1, "first Nostr command in an unset life commits NOSTR and saves the life token");
    do_door(DOOR_BTC);
    CHECK(g_door == DOOR_NOSTR && g_sig_out[5] == 0xEE, "DOORBTC after that is refused (first-wins)");
    CHECK(!door_permits(G0_CMD_BTCSIGN_INIT) && !door_permits(G0_CMD_DOORKEYS) && !door_permits(G0_CMD_MODEBTC) && !door_permits(G0_CMD_MSGSIGN_INIT),
          "BTC commands refused in that life");
    int cmds[] = { G0_CMD_SIGN_INIT, G0_CMD_ECDH, G0_CMD_PUBKEY, G0_CMD_CACHEKEY, G0_CMD_SESSIONTEST };
    int all = 1;
    for (unsigned k = 0; k < 5; k++) { g_door = DOOR_UNSET; door_autocommit(cmds[k]); if (g_door != DOOR_NOSTR) all = 0; }
    CHECK(all, "every Nostr key command (SIGN/ECDH/PUBKEY/CACHEKEY/SESSIONTEST) auto-commits");
    g_door = DOOR_BTC; door_autocommit(G0_CMD_SIGN_INIT);
    CHECK(g_door == DOOR_BTC && !door_permits(G0_CMD_SIGN_INIT), "a BTC life is never flipped by a Nostr command; SIGN still refused");

    /* finding 3: WIPEALL ordering */
    se_full(); do_wipeall();
    CHECK(g_sig_out[5] == 0 && !se_exists[O_WSEED] && !se_exists[O_MODE] && !se_exists[O_RECOVER] && g_recover_gone,
          "normal WIPEALL: seed key, latch and RECOVER all deleted");
    CHECK(!attacker_gets_seed_dec(), "after a full wipe, re-creating the latch at BTC opens nothing (seed key gone)");

    se_full(); se_refuse[O_WSEED] = 1; g_recover_gone = 0; do_wipeall();
    CHECK(g_sig_out[5] == 0xD1, "seed key delete refused -> WIPEALL stops with 0xD1");
    CHECK(se_exists[O_WSEED] && se_exists[O_MODE] && se_exists[O_RECOVER] && !g_recover_gone,
          "... latch and RECOVER kept, so K_SE is kept and the wipe can be retried");
    CHECK(!attacker_gets_seed_dec(), "... and the latch cannot be re-created at BTC (it was never deleted)");

    se_full(); se_exists[O_WSEED] = 0; do_wipeall();
    CHECK(g_sig_out[5] == 0 && !se_exists[O_MODE] && !se_exists[O_RECOVER], "seed key already absent (daily-PIN wipe path) -> WIPEALL completes");

    se_full(); relay_drops_at = O_WSEED; g_recover_gone = 0; do_wipeall();
    CHECK(se_exists[O_WSEED] && se_exists[O_MODE] && !g_recover_gone,
          "relay skips the seed delete and forges 'absent': the MAC chain breaks, latch survives");
    CHECK(!attacker_gets_seed_dec(), "... so the forged-absent trick gives no BTC latch");

    /* N2 (20 Oct 2026): the G0 auth object is deleted last-but-one, only
     * once everything naming it is gone; a legacy object (no RECOVER right)
     * does not stop the wipe. */
    se_full(); g_recover_gone = 0; do_wipeall();
    CHECK(g_sig_out[5] == 0 && !se_exists[O_G0AUTH] && !se_exists[O_RECOVER] && g_recover_gone,
          "N2: normal WIPEALL also deletes the G0 auth object, RECOVER still last");
    se_full(); se_refuse[O_WSEED] = 1; g_recover_gone = 0; do_wipeall();
    CHECK(se_exists[O_G0AUTH] && se_exists[O_RECOVER], "N2: seed key refused -> G0 auth object kept with the latch and RECOVER");
    se_full(); se_refuse[O_WDAILY] = 1; g_recover_gone = 0; do_wipeall();
    CHECK(g_sig_out[5] == 0xD0 && se_exists[O_G0AUTH] && !se_exists[O_RECOVER] && g_recover_gone,
          "N2: daily wrap key refused -> G0 auth object skipped (0xD0), RECOVER still deleted so K_SE may be forgotten");
    se_full(); se_refuse[O_G0AUTH] = 1; g_recover_gone = 0; do_wipeall();
    CHECK(g_sig_out[5] == 0xD0 && se_exists[O_G0AUTH] && !se_exists[O_RECOVER] && g_recover_gone,
          "N2: legacy G0 auth object (no RECOVER right, 6986) -> reported 0xD0, wipe completes");
    se_full(); se_exists[O_G0AUTH] = 0; g_recover_gone = 0; do_wipeall();
    CHECK(g_sig_out[5] == 0 && !se_exists[O_RECOVER], "N2: G0 auth object already absent -> clean wipe");

    /* the pre-fix behaviour, for the record: any path that deletes the latch
     * while the seed key lives hands the SE a BTC latch with no S */
    se_full(); se_exists[O_MODE] = 0;
    CHECK(attacker_gets_seed_dec(), "MODEL CHECK: latch deleted while seed key lives = spend-PIN DEC in any life (the hole)");

    printf(fails ? "\n%d FAILED\n" : "\nall finding 3/4 + N2 G0 checks passed\n", fails);
    return fails != 0;
}
