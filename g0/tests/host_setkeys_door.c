/* 22 Nov 2026 host test for audit #53 (G0 v21). Runs the REAL do_setkeys from
 * src/main.c (extracted by run_setkeys_door.sh) with flash stubbed:
 *   door UNSET  -> SETKEYS accepted, seal window opens (honest onboarding)
 *   door NOSTR  -> SETKEYS refused, seal window stays shut (the swap chain)
 *   door BTC / PASSKEY -> refused too. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#define KSE_LEN 16
#define KG0_LEN 32
#define KMODE_LEN 32
#define KEYS_LEN (KSE_LEN + KG0_LEN + KMODE_LEN + 1)
#define SE_GEN_MAX 30
#define DOOR_UNSET 0
#define DOOR_NOSTR 1
#define DOOR_BTC 2
#define DOOR_PASSKEY 3
static uint8_t g_kse[KSE_LEN], g_kg0[KG0_LEN], g_kmode[KMODE_LEN];
static uint8_t g_keys_valid, g_recover_gone, g_door, g_door1_locked, g_seal_window;
static uint8_t g_wiped_life;
static uint8_t g_pk_scratch_own, g_pk_dirty, g_pk_master_done, g_true_pk_ok;
static uint8_t g_keys_in[KEYS_LEN]; static volatile uint8_t g_keys_in_valid;
static uint8_t g_sig_out[64];
static int ss_present(void) { return 0; }
static int ss_erase(void) { return 1; }
static int ks_store(const uint8_t *a, const uint8_t *b, const uint8_t *c, uint8_t g) { (void)a; (void)b; (void)c; (void)g; return 1; }
static void gen_set(uint8_t g) { (void)g; }
static void uv_clear(void) {}
static void entropy_mix(const uint8_t *p, size_t n) { (void)p; (void)n; }
#include "extracted_setkeys.inc"
static int fails = 0;
static void run2(uint8_t door, uint8_t wiped, int want_ok);
static void run(uint8_t door, int want_ok) { run2(door, 0, want_ok); }
static void run2(uint8_t door, uint8_t wiped, int want_ok) {
    g_wiped_life = wiped;
    g_door = door; g_keys_valid = 0; g_seal_window = 0; g_recover_gone = 1;
    memset(g_keys_in, 0x5A, KEYS_LEN); g_keys_in[KEYS_LEN - 1] = 2; g_keys_in_valid = 1;
    int rc = do_setkeys();
    int ok = (rc == 0);
    int pass = want_ok ? (ok && g_seal_window == 1 && g_keys_valid == 1)
                       : (!ok && g_seal_window == 0 && g_keys_valid == 0);
    printf("%s  door=%u wiped=%u SETKEYS rc=%d seal_window=%u keys_valid=%u (want %s)\n", pass ? "PASS" : "FAIL",
           door, wiped, rc, g_seal_window, g_keys_valid, want_ok ? "accepted" : "refused");
    if (!pass) fails++;
}
int main(void) {
    run(DOOR_UNSET, 1);
    run(DOOR_NOSTR, 0);
    run(DOOR_BTC, 0);
    run(DOOR_PASSKEY, 0);
    run2(DOOR_UNSET, 1, 0);   /* v22 (#60): the life that ran WIPEKEYS cannot re-key, even UNSET */
    printf(fails ? "RESULT: FAIL\n" : "RESULT: SETKEYS opens the seal window only in a door-UNSET life with no wipe in it\n");
    return fails != 0;
}
