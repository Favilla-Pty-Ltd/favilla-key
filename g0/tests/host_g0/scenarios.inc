/* scenarios for the harness (audit 21 Nov 2026) */
static int fails = 0;
#define CHECK(c, msg) do { if (c) printf("  ok   %s\n", msg); else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static wallet_t U;   /* the user's wallet */
static void setup_user(void) {
    memset(fse, 0, sizeof fse);
    h_flash_init();
    wallet_make(&U, 9, 0x11);
    g0_power_on(1);
    int r = onboard(&U);
    CHECK(r == 0, "honest onboarding (generation 9)");
    g0_power_on(1);
    r = life_btc(&U, U.mfp, 1);
    CHECK(r == 0, "first BTC life opens the wallet with the spend PIN");
    printf("       wallet fingerprint %02x%02x%02x%02x\n", U.mfp[0], U.mfp[1], U.mfp[2], U.mfp[3]);
}

/* S1: the door model as designed */
static void s1_doors(void) {
    printf("S1 honest lives and the obvious attacks\n");
    setup_user();
    g0_power_on(1);
    CHECK(life_nostr(&U) == 0, "NOSTR life: door NOSTR, latch NOSTR, PUBKEY works");
    uint8_t m[4];
    hreset(); hcmd(G0_CMD_DOORBTC);
    CHECK(g_door == DOOR_NOSTR, "DOORBTC in a NOSTR life: first-wins keeps NOSTR");
    int r = btc_unlock_and_keys(U.gen, U.spin, m, 0);
    CHECK(r != 0, "even WITH the spend PIN, the BTC door does not open in a NOSTR life");
    printf("       before reset: door %u arms r%u b%u bkp %08X\n", g_door, g_mode_reset_arm, g_mode_btc_arm, fake_tamp.BKP0R);
    g0_power_on(0);   /* a non-power reset keeps the life */
    printf("       after reset: door %u arms r%u b%u resumed %d\n", g_door, g_mode_reset_arm, g_mode_btc_arm, g_life_resumed);
    CHECK(g_door == DOOR_NOSTR && !g_mode_reset_arm && g_life_resumed, "NRST/soft reset restores the life token (door NOSTR, MODERESET one-shot spent)");
    g0_power_on(1);
    r = life_btc(&U, m, 1);
    CHECK(r == 0 && !memcmp(m, U.mfp, 4), "after a power cycle the BTC door opens again with the same wallet");
}

/* S2: issue #53, the seed swap from a NOSTR life */
static void s2_seed_swap(int expect_blocked) {
    printf("S2 NOSTR-life attacker: WIPEALL, WIPEKEYS, SETKEYS, re-onboard with its own seed\n");
    setup_user();
    g0_power_on(1);
    CHECK(life_nostr(&U) == 0, "NOSTR life");
    /* attacker */
    hreset(); hcmd(G0_CMD_WIPEALL);
    printf("       WIPEALL diag rc %02X\n", g_sig_out[5]);
    hreset(); int st = hcmd(G0_CMD_WIPEKEYS);
    printf("       WIPEKEYS status %02X keys_valid %d\n", st, g_keys_valid);
    wallet_t A; wallet_make(&A, 10, 0x66);
    int r = onboard_x(&A, 1);
    printf("       attacker onboarding in the NOSTR life: %d\n", r);
    /* next real power cycle: the user opens Bitcoin */
    g0_power_on(1);
    uint8_t m[4]; memset(m, 0, 4);
    int b = life_btc(&U, m, 1);
    int b2 = -99; uint8_t m2[4] = {0};
    if (b != 0) { g0_power_on(1); b2 = life_btc(&A, m2, 1); }
    printf("       user's own PIN: %d, attacker's PIN: %d fp %02x%02x%02x%02x\n", b, b2, m2[0], m2[1], m2[2], m2[3]);
    int swapped = (r == 0 && b2 == 0 && memcmp(m2, U.mfp, 4) != 0);
    if (expect_blocked) CHECK(!swapped, "the G0 refused the swap (seed page cannot change in a NOSTR life)");
    else CHECK(swapped, "reproduced: the BTC door now opens an attacker-chosen wallet");
}

/* S5: the ARM step accepts any PIN session's extend. An attacker with code in
 * a BTC-door boot (needs persistence), the daily PIN and an inner packet seen
 * in an earlier BTC life gets DOORKEYS without the spend PIN. */
static void s5_arm_by_daily(void) {
    printf("S5 ARM from the daily PIN, inner packet replayed (needs code in a BTC-door boot)\n");
    setup_user();   /* the first BTC life left the inner packet in g_inner_pkt */
    uint8_t pkt[96]; memcpy(pkt, g_inner_pkt, 96);
    uint8_t nostrc[32], armc[32]; consts(nostrc, armc);
    g0_power_on(1);
    hreset(); hcmd(G0_CMD_DOOR1LOCK); hreset(); hcmd(G0_CMD_MODERESET); hreset(); hcmd(G0_CMD_DOORBTC);
    int armed = pin_extend(PIN_D(U.gen), U.dpin, O_MODE(U.gen), armc);
    hreset(); hcmd(G0_CMD_MODEBTC); int mint = g_sig_out[5];
    hreset(); hw(G0_REG_SEED_IN, pkt, 96); hcmd(G0_CMD_DOORKEYS);
    int ok = g_status == G0_ST_SIG_READY && g_btc_out[5] == 0 && !memcmp(g_btc_out + 6, U.mfp, 4);
    printf("       daily-PIN arm %d, MODEBTC diag %02X, DOORKEYS rc %02X\n", armed, mint, g_btc_out[5]);
    CHECK(ok, "documented: with the daily PIN and a replayed inner packet the G0 opens the wallet, no spend PIN");
    /* the same with the passkey PIN would need a passkey PIN object; not modelled */
}

/* S6: the same swap from a life whose door is still UNSET (a radio up
 * before the door commit, issue #55). FIX53 alone does not cover this. */
static void s6_unset_window(void) {
    printf("S6 attacker in the UNSET window of a fresh boot (radio before the door commit)\n");
    setup_user();
    g0_power_on(1);
    hreset(); hcmd(G0_CMD_WIPEALL);
    hreset(); hcmd(G0_CMD_WIPEKEYS);
    wallet_t A; wallet_make(&A, 10, 0x77);
    int r = onboard_x(&A, 1);
    g0_power_on(1);
    uint8_t m2[4] = {0}; int b2 = life_btc(&A, m2, 1);
    int swapped = (r == 0 && b2 == 0 && memcmp(m2, U.mfp, 4) != 0);
    printf("       attacker onboarding %d, attacker wallet opens %d\n", r, b2);
    CHECK(!swapped, "the G0 refused the swap in the UNSET window (G0 v22: no SETKEYS in the life that ran WIPEKEYS, #60)");
}
