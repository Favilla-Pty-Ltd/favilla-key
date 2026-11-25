/* libFuzzer over the real VAULT handler (vault_glue.inc), v17 TOTP included.
 * The host test's stubs (a mock SE) are reused; its main() is renamed.
 * Invariants checked on every input, beyond ASan/UBSan:
 *   - a TOTP record's secret never appears in VAULT_OUT, whatever the op;
 *   - OPEN of a kind 3 record never succeeds;
 *   - the output length the G0 reports never exceeds the output buffer. */
#define main host_vault_main
#include "host_vault.c"
#undef main
static int s_init;
static uint8_t s_rec[3][600]; static size_t s_recn[3];
static const char SECRET[] = "FUZZ-SECRET-0123456789";   /* 22 bytes */
static void init_once(void) {
    mbedtls_ecp_group_init(&G); mbedtls_ecp_group_load(&G, MBEDTLS_ECP_DP_SECP256R1);
    for (int i = 0; i < 32; i++) g_kg0[i] = (uint8_t)(0x5A ^ i);
    v3_value(fake_pcr);   /* v19: a passkey window open */
    uint8_t spk[32]; for (int i = 0; i < 32; i++) spk[i] = (uint8_t)(0xA0 + i);
    g_door = DOOR_PASSKEY; g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING;
    seal_master(spk);
    uint8_t in[600], pt[300]; size_t n;
    /* 0: a password record (kind 2), 1: a TOTP record (kind 3), 2: a passkey-kind record (kind 1) */
    const uint8_t h2[13] = {1,1,1,1,1,1,1,1, 0,0,0,1, VLT_KIND_PASSWORD}, h3[13] = {2,2,2,2,2,2,2,2, 0,0,0,2, VLT_KIND_TOTP}, h1[13] = {3,3,3,3,3,3,3,3, 0,0,0,3, 1};
    n = 0; pt[n++] = 10; memcpy(pt + n, "github.com", 10); n += 10; pt[n++] = 4; memcpy(pt + n, "josh", 4); n += 4; pt[n++] = 6; memcpy(pt + n, "pass12", 6); n += 6;
    run(VLT_OP_SEAL, in, mk_seal_in(in, h2, pt, n), s_rec[0], &s_recn[0]);
    n = 0; pt[n++] = 6; memcpy(pt + n, "GitHub", 6); n += 6; pt[n++] = 4; memcpy(pt + n, "josh", 4); n += 4; pt[n++] = 22; memcpy(pt + n, SECRET, 22); n += 22; pt[n++] = 6; pt[n++] = 30;
    run(VLT_OP_SEAL, in, mk_seal_in(in, h3, pt, n), s_rec[1], &s_recn[1]);
    n = 0; pt[n++] = 8; memcpy(pt + n, "site.com", 8); n += 8; for (int i = 0; i < 40; i++) pt[n++] = (uint8_t)i;
    run(VLT_OP_SEAL, in, mk_seal_in(in, h1, pt, n), s_rec[2], &s_recn[2]);
    s_init = 1;
}
static int has_secret(void) { for (size_t i = 0; i + 22 <= sizeof(g_vlt_out); i++) if (!memcmp(g_vlt_out + i, SECRET, 22)) return 1; return 0; }
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    if (!s_init) init_once();
    if (n < 2) return 0;
    g_door = DOOR_PASSKEY; g_vlt_open_left = VLT_PER_SITTING; g_vlt_tag_left = VLT_PER_SITTING; g_lbl_used = 0;
    if (d[1] & 0x80) g_totp_last = 0;
    const uint8_t op = d[0] % 9, mode = d[1] % 4;
    uint8_t buf[VLT_IN_LEN]; size_t bl = 0;
    const uint8_t *p = d + 2; size_t pn = n - 2;
    if (mode == 0) { bl = pn > VLT_IN_LEN - 3 ? VLT_IN_LEN - 3 : pn; memcpy(buf, p, bl); }
    else {
        const int r = mode - 1; size_t o = 0;
        if (op == VLT_OP_TOTP) { for (int i = 0; i < 8; i++) buf[o++] = pn > (size_t)i ? p[i] : 0; p += pn > 8 ? 8 : pn; pn -= pn > 8 ? 8 : pn; }
        memcpy(buf + o, s_rec[r], s_recn[r]); bl = o + s_recn[r];
        /* the rest of the input: pairs (position, xor) over the record, then a length change */
        for (size_t i = 0; i + 1 < pn; i += 2) buf[o + (p[i] % s_recn[r])] ^= p[i + 1];
        if (pn & 1) { int dl = (int)(p[pn - 1] % 33) - 16; if ((int)bl + dl > 0 && bl + dl <= VLT_IN_LEN - 3) bl += dl; }
    }
    uint8_t out[600]; size_t on = 0;
    const uint8_t rc = run(op, buf, bl, NULL, NULL);
    on = ((size_t)g_vlt_out[8] << 8) | g_vlt_out[9];
    if (on > VLT_OUT_LEN - 12) __builtin_trap();                       /* the length can never run past the buffer */
    if (has_secret()) __builtin_trap();                                /* the TOTP secret never leaves */
    if (op == VLT_OP_OPEN && rc == 0 && mode == 2) __builtin_trap();   /* OPEN of the TOTP record must fail */
    (void)out;
    return 0;
}
