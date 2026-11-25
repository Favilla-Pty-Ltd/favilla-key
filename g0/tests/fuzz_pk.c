/* libFuzzer over the real PKSIGN handler (pk_glue.inc, G0 v16 signer, v18
 * hedged nonces), with the host test's mock SE; its main() is renamed. The
 * input is PK_IN (op || nonce || tag || rp || hash) and the mock SE's faults.
 * Beyond ASan/UBSan: the per-site key k, the master and the scratch never
 * appear in BTC_OUT, and the budget never goes below zero. */
#define main host_pk_main
#include "host_pk.c"
#undef main
static int s_init;
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    if (!s_init) {
        mbedtls_ecp_group_init(&G); mbedtls_ecp_group_load(&G, MBEDTLS_ECP_DP_SECP256R1);
        for (int i = 0; i < 32; i++) g_kg0[i] = (uint8_t)(0x5A ^ i);
        v3_value(fake_pcr);
        g_seal_window = 1; g_pk_master_done = 0; seal_master(KAT_SPK); g_seal_window = 0;
        s_init = 1;
    }
    if (n < 2) return 0;
    reset_counts();
    g_pk_sign_left = d[0] & 0x3F;                    /* 0..63: the budget edges */
    if (d[1] & 0x01) fail_open = 1;
    if (d[1] & 0x02) fail_sign = 1;
    if (d[1] & 0x04) fail_create = 1;
    give_pkm(); v3_value(fake_pcr); g_door = DOOR_PASSKEY; pcr_fail = 0;   /* v19: a window open by default */
    if (d[1] & 0x40) { g_pkm_in[d[0] % PKM_IN_LEN] ^= (uint8_t)(1 + (d[1] >> 7)); }   /* v19: a damaged PKM_IN */
    if (d[1] & 0x80) { fake_pcr[d[0] & 31] ^= 1; }                                  /* v19: the latch off V_3 */
    if ((d[0] & 0xC0) == 0xC0) g_door = (uint8_t)(d[1] & 3);                         /* v19: another door */
    memset(g_pk_in, 0, PK_IN_LEN);
    size_t m = n - 2 > PK_IN_LEN ? PK_IN_LEN : n - 2; memcpy(g_pk_in, d + 2, m);
    if (d[1] & 0x08) g_pk_in[0] = (uint8_t)(1 + (g_pk_in[0] & 1));   /* bias to the real ops */
    if (d[1] & 0x10) memcpy(g_pk_in + 33, KAT_RP, 32);
    if (d[1] & 0x20) { pk_tag(KAT_SPK, g_pk_in + 1, g_pk_in + 33, g_pk_in + 17); }   /* a valid tag for that nonce and rp */
    g_pk_in_valid = 1;
    const int before = g_pk_sign_left;
    do_pksign();
    if (master_obj_touched) __builtin_trap();                                       /* v19: the G0 never asks for K_PK or the master objects */
    if ((d[1] & 0xC0) && g_btc_out[5] == 0 && g_pk_in[0] == PK_OP_SIGN && (d[1] & 0x40)) __builtin_trap();   /* v19: a damaged PKM_IN never signs */
    if (g_pk_sign_left < 0 || g_pk_sign_left > before) __builtin_trap();
    uint8_t k[32];
    if (pk_derive(KAT_SPK, g_pk_in[0] ? g_pk_in + 1 : g_btc_out + 12, g_pk_in + 33, k) == 0)
        for (size_t i = 0; i + 32 <= BTC_OUT_LEN; i++) if (!memcmp(g_btc_out + i, k, 32)) __builtin_trap();   /* the site key never leaves */
    for (size_t i = 0; i + 32 <= BTC_OUT_LEN; i++) if (!memcmp(g_btc_out + i, KAT_SPK, 32)) __builtin_trap();       /* nor the master */
    return 0;
}
