/* S8 (audit 22 Nov 2026): raw attacker. Every command byte 0x00..0x3F and every
 * input register, exact length most of the time and random content, from a
 * NOSTR life and from a VAULT life. Run under ASan/UBSan: any memory error in
 * any handler (Emberwill glue, PKSIGN, VAULT, door, TOTP ...) aborts. The
 * two-door invariants are checked after every step as in S3. */
struct s8reg { uint8_t reg; size_t len; };
static const struct s8reg S8R[] = {
    { G0_REG_HASH_IN, 32 }, { G0_REG_KEYS_IN, KEYS_LEN }, { G0_REG_SEED_IN, SEED_IN_LEN }, { G0_REG_BTC_IN, BTC_REQ_LEN },
    { G0_REG_ENT_IN, SEED_IN_LEN }, { G0_REG_PASS_IN, PASS_IN_LEN }, { G0_REG_STORE_IN, STORE_IN_LEN }, { G0_REG_AE_IN, AE_IN_LEN },
    { G0_REG_AE_T, 32 }, { G0_REG_PK_IN, PK_IN_LEN }, { G0_REG_PKM_IN, PKM_IN_LEN }, { G0_REG_VAULT_IN, VLT_IN_LEN },
    { G0_REG_EM_HDR, EM_HDR_IN_LEN }, { G0_REG_EM_SET, EP_SET_LEN }, { G0_REG_EM_CHUNK, EM_CHUNK_IN_LEN }, { G0_REG_EM_ARG, EM_ARG_LEN },
    { G0_REG_RELAY_IN, 64 },
};
static void s8_write(void) {
    const struct s8reg *r = &S8R[rnd() % (sizeof S8R / sizeof S8R[0])];
    uint8_t b[598]; size_t n = r->len;
    if (rnd() % 16 == 0) n = rnd() % 597;
    if (n > sizeof b) n = sizeof b;
    int style = rnd() % 4;
    for (size_t i = 0; i < n; i++) b[i] = style == 0 ? 0 : style == 1 ? (uint8_t)rnd() : style == 2 ? (uint8_t)(rnd() % 4) : (uint8_t)(i < 8 ? rnd() : 0);
    if (r->reg == G0_REG_EM_CHUNK && n >= 4) { uint16_t tot = (uint16_t)(rnd() % 1200); b[0] = (uint8_t)tot; b[1] = (uint8_t)(tot >> 8); b[2] = (uint8_t)(rnd() % 20); b[3] = 0; }
    hw(r->reg, b, n);
}
static int s8_search(int iters, int steps, int vault) {
    for (int it = 0; it < iters; it++) {
        memset(fse, 0, sizeof fse); memset(h_flash, 0xFF, 0x20000);
        wallet_make(&U, 9, 0x11); g0_power_on(1);
        if (onboard(&U) != 0) { printf("setup failed\n"); return -1; }
        g0_power_on(1); if (life_btc(&U, U.mfp, 0) != 0) { printf("setup btc failed\n"); return -1; }
        { uint8_t k; ss_load(&k, NULL, user_ihash); }
        g0_power_on(1);
        if (vault) { if (life_vault(&U) != 0) { printf("setup vault failed\n"); return -1; } }
        else if (life_nostr(&U) != 0) { printf("setup nostr failed\n"); return -1; }
        viol = 0;
        for (int s = 0; s < steps && !viol; s++) {
            int nw = rnd() % 4; for (int w = 0; w < nw; w++) s8_write();
            uint8_t c = (uint8_t)(rnd() % 0x40); if (c == 0x10 || c == 0x17) c = 0x00;   /* Stop mode needs a real wake */
            if (rnd() % 3 == 0) hreset();
            hcmd(c);
            char what[32]; snprintf(what, sizeof what, "raw cmd %02X", c);
            check_invariants(what, U.gen);
        }
        if (viol) { printf("  VIOLATION (iteration %d): %s\n", it, vmsg); return 1; }
    }
    return 0;
}
static void s8_raw(void) {
    int iters = getenv("ITERS8") ? atoi(getenv("ITERS8")) : 200;
    if (getenv("SEED")) { rs ^= strtoull(getenv("SEED"), NULL, 10) * 0x9E3779B97F4A7C15ull; if (!rs) rs = 1; }
    printf("S8 raw attacker: every command byte, every register (NOSTR life)\n");
    int f = s8_search(iters, 60, 0);
    printf("  search: %s after up to %d iterations\n", f ? "VIOLATION found" : "no violation", iters);
    printf("S8 raw attacker: every command byte, every register (VAULT life)\n");
    f = s8_search(iters, 60, 1);
    printf("  search: %s after up to %d iterations\n", f ? "VIOLATION found" : "no violation", iters);
}
