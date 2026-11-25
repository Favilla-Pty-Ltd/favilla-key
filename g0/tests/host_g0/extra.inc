/* Random attacker search (audit 21 Nov 2026). After an honest NOSTR life,
 * the attacker owns the ESP32 and the daily PIN (the user typed it), not the
 * spend PIN. Every step it sends a G0 command with chosen inputs, or uses the
 * daily-PIN session or anonymous SE access. After every step the invariants
 * of the two-door model are checked against the real G0 state. Variant
 * KNOWN_INNER gives the attacker the inner packet from an earlier BTC life. */
static uint64_t rs = 88172645463325252ull;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)rs; }
static const uint8_t CMDS[] = {
    G0_CMD_PROVISION, G0_CMD_ECDH, G0_CMD_PUBKEY, G0_CMD_CACHEKEY, G0_CMD_SETKEYS, G0_CMD_WIPEKEYS, G0_CMD_SESSIONTEST,
    G0_CMD_MODERESET, G0_CMD_MODEBTC, G0_CMD_SEEDSEAL, G0_CMD_DOORKEYS, G0_CMD_DOORNOSTR, G0_CMD_DOORBTC, G0_CMD_DOORPASSKEY,
    G0_CMD_MODEDOOR, G0_CMD_ENTSEAL, G0_CMD_WIPEALL, G0_CMD_SEEDSTORE, G0_CMD_SEEDGET, G0_CMD_DOOR1LOCK,
    G0_CMD_SIGN_INIT, G0_CMD_AE_FINISH, G0_CMD_BTCSIGN_INIT, G0_CMD_MSGSIGN_INIT, G0_CMD_PKMASTER, G0_CMD_PKSCRUB,
    G0_CMD_UVSET, G0_CMD_UVCHECK, G0_CMD_UVCLEAR, G0_CMD_RESET,
    G0_CMD_EM_STATUS, G0_CMD_EM_LIFE, G0_CMD_EM_RELEASE, G0_CMD_EM_PULSE, G0_CMD_EM_AWAY, G0_CMD_EM_SET, G0_CMD_EM_CLEAR,
};
static int viol = 0; static char vmsg[256];
static uint8_t user_ihash[32];
static void put_random_regs(int known_inner, wallet_t *A) {
    uint8_t b[420];
    int k = rnd() % 10;
    switch (k) {
    case 0: for (int i = 0; i < 96; i++) b[i] = (uint8_t)rnd(); if (rnd() & 1) memcpy(b + 64, INNER_PKT_MAGIC, 4); hw(G0_REG_SEED_IN, b, 96); break;
    case 1: if (known_inner && g_inner_known) hw(G0_REG_SEED_IN, g_inner_pkt, 96); else { memset(b, 0, 96); memcpy(b, A->seed, 64); hw(G0_REG_SEED_IN, b, 96); } break;
    case 2: memcpy(b, A->kse, 16); memcpy(b + 16, A->kg0, 32); memcpy(b + 48, A->S, 32); b[80] = (uint8_t)(1 + rnd() % 20); hw(G0_REG_KEYS_IN, b, KEYS_LEN); break;
    case 3: b[0] = (rnd() & 1) ? SS_KIND_SEED : SS_KIND_ENTROPY; for (int i = 1; i < 97; i++) b[i] = (uint8_t)rnd(); hw(G0_REG_STORE_IN, b, 97); break;
    case 4: for (int i = 0; i < 32; i++) b[i] = (uint8_t)rnd(); hw(G0_REG_HASH_IN, b, 32); break;
    case 5: memset(b, 0, 416); b[0] = (uint8_t)(rnd() % 4); for (int i = 1; i < 416; i++) if (rnd() % 4 == 0) b[i] = (uint8_t)rnd(); hw(G0_REG_BTC_IN, b, 416); break;
    case 6: memset(b, 0, 64); if (rnd() & 1) for (int i = 0; i < 64; i++) b[i] = (uint8_t)rnd(); else for (int i = 32; i < 64; i++) b[i] = (uint8_t)rnd(); hw(G0_REG_AE_IN, b, 64); break;
    case 7: for (int i = 0; i < 32; i++) b[i] = (uint8_t)rnd(); hw(G0_REG_AE_T, b, 32); break;
    case 8: memset(b, 0, 96); b[0] = 12; for (int i = 1; i < 17; i++) b[i] = (uint8_t)rnd(); hw(G0_REG_ENT_IN, b, 96); break;
    default: memset(b, 0, 101); b[0] = (uint8_t)(rnd() % 8); hw(G0_REG_PASS_IN, b, 101); break;
    }
}
static void check_invariants(const char *what, int gen) {
    if (viol) return;
    uint8_t btcv[32]; btc_value(U.S, btcv);
    fse_obj_t *m = fse_find(O_MODE(gen));
    if (g_door != DOOR_BTC && m && !memcmp(m->val, btcv, 32) && fse_find(O_SEEDK(gen))) { viol = 1; snprintf(vmsg, sizeof vmsg, "latch reads BTC (seed key still there) in a door-%u life after %s", g_door, what); return; }
    if (g_door != DOOR_BTC && g_status == G0_ST_SIG_READY &&
        ((g_btc_out[0] == 'D' && g_btc_out[1] == 'K' && g_btc_out[5] == 0) ||
         (g_btc_out[0] == 'B' && g_btc_out[1] == 'S' && g_btc_out[5] == 0) ||
         (g_btc_out[0] == 'M' && g_btc_out[1] == 'S' && g_btc_out[5] == 0))) { viol = 1; snprintf(vmsg, sizeof vmsg, "seed-derived BTC output in a door-%u life after %s", g_door, what); return; }
    if (g_door != DOOR_BTC && (g_ae.kind == AE_KIND_ECDSA || g_ae.kind == AE_KIND_ECDSA_RC)) { viol = 1; snprintf(vmsg, sizeof vmsg, "a Bitcoin signature pending in a door-%u life after %s", g_door, what); return; }
    if (g_door != DOOR_UNSET && g_seal_window) { viol = 1; snprintf(vmsg, sizeof vmsg, "seal window open in a door-%u life after %s", g_door, what); return; }
    { uint8_t k = 0, ih[32];
      if (ss_load(&k, NULL, ih) && memcmp(ih, user_ihash, 32) != 0) { viol = 1; snprintf(vmsg, sizeof vmsg, "seed page holds a different seed after %s", what); return; } }
}
static int search_x(int iters, int steps, int known_inner, int verbose, int vault) {
    int found = 0;
    for (int it = 0; it < iters && !found; it++) {
        memset(fse, 0, sizeof fse); memset(h_flash, 0xFF, 0x20000);
        wallet_make(&U, 9, 0x11); g0_power_on(1);
        if (onboard(&U) != 0) { printf("setup failed\n"); return -1; }
        g0_power_on(1); if (life_btc(&U, U.mfp, 0) != 0) { printf("setup btc failed\n"); return -1; }
        { uint8_t k; ss_load(&k, NULL, user_ihash); }
        g0_power_on(1);
        if (vault) { if (life_vault(&U) != 0) { printf("setup vault failed\n"); return -1; } }
        else if (life_nostr(&U) != 0) { printf("setup nostr failed\n"); return -1; }
        if (!known_inner) g_inner_known = 0;
        wallet_t A; wallet_make(&A, 9 + 1 + (int)(rnd() % 3), (uint8_t)(0x40 + rnd() % 64));
        uint8_t nostrc[32], armc[32]; consts(nostrc, armc);
        char trace[4096]; int tl = 0; trace[0] = 0;
        viol = 0;
        for (int s = 0; s < steps && !viol; s++) {
            int a = rnd() % 100; char what[64];
            if (a < 70) {
                int nregs = rnd() % 3; for (int r = 0; r < nregs; r++) put_random_regs(known_inner, &A);
                uint8_t c = CMDS[rnd() % sizeof CMDS];
                if (rnd() % 4) hreset();
                hcmd(c);
                snprintf(what, sizeof what, "cmd %02X", c);
            } else if (a < 82) {
                int which = rnd() % 4; uint8_t e[32];
                if (which == 0) memcpy(e, nostrc, 32); else if (which == 1) memcpy(e, armc, 32); else if (which == 2) memcpy(e, MODE_CONST_SPENT, 32); else for (int i = 0; i < 32; i++) e[i] = (uint8_t)rnd();
                if (vault) pin_extend(PIN_P(U.gen), U.ppin, O_MODE(U.gen), e); else pin_extend(PIN_D(U.gen), U.dpin, O_MODE(U.gen), e);
                snprintf(what, sizeof what, "daily extend %d", which);
            } else if (a < 86) {
                uint32_t ids[] = { O_SEEDK(U.gen), O_SCALAR(U.gen), O_DAILYK(U.gen) };
                fse_obj_t *o = fse_find(ids[rnd() % 3]);
                if (o && (fse_rights(o, PIN_D(U.gen)) & FSE_R_DELETE)) o->used = 0;
                snprintf(what, sizeof what, "daily delete");
            } else if (a < 90) {
                /* anonymous create: a latch at another generation already at a BTC value it can compute */
                int g = 9 + (int)(rnd() % 4); uint8_t v[32]; if (rnd() & 1) btc_value(U.S, v); else btc_value(A.S, v);
                fse_obj_t *o = fse_create(O_MODE(g), FSE_K_PCR); if (o) { memcpy(o->val, v, 32); }
                snprintf(what, sizeof what, "anon create latch gen %d", g);
            } else if (a < 94) {
                int r = onboard_x(&A, 1); snprintf(what, sizeof what, "attacker onboarding gen %d -> %d", A.gen, r);
            } else {
                hreset(); snprintf(what, sizeof what, "RESET");
            }
            tl += snprintf(trace + tl, sizeof trace - (size_t)tl, "%s; ", what); if (tl > 3800) tl = 3800;
            check_invariants(what, U.gen);
            if (!viol && g_keys_valid && g_gen != (uint8_t)U.gen) check_invariants(what, g_gen);
        }
        if (viol) { found = 1; printf("  VIOLATION (iteration %d): %s\n  trace: %s\n", it, vmsg, trace); }
        if (verbose && it % 500 == 0) printf("  ... %d iterations\n", it);
    }
    return found;
}
static int search(int iters, int steps, int known_inner, int verbose) { return search_x(iters, steps, known_inner, verbose, 0); }
static void extra_scenarios(void) {
    printf("S3 random attacker in a NOSTR life (daily PIN known, spend PIN not)\n");
    int iters = getenv("ITERS") ? atoi(getenv("ITERS")) : 300;
    if (getenv("SEED")) { rs ^= strtoull(getenv("SEED"), NULL, 10) * 0x9E3779B97F4A7C15ull; if (!rs) rs = 1; }
    int f = search(iters, 40, 0, 1);
    printf("  search: %s after up to %d iterations\n", f ? "VIOLATION found" : "no violation", iters);
    printf("S4 same, and the attacker also holds the inner packet from an earlier BTC life\n");
    f = search(iters, 40, 1, 1);
    printf("  search: %s after up to %d iterations\n", f ? "VIOLATION found" : "no violation", iters);
    printf("S7 random attacker in a VAULT (Bluetooth) life (passkey PIN known)\n");
    f = search_x(iters, 40, 0, 1, 1);
    printf("  search: %s after up to %d iterations\n", f ? "VIOLATION found" : "no violation", iters);
}
