/* CBMC bounded proof harness for lib/scp03 + the MODE_PCR TLV walk.
 * Claim proved: for EVERY response the transport can deliver (any length
 * 0..514, any bytes) and every command mix the G0 issues, scp03.c and the
 * TLV walk perform no out-of-bounds read/write, no pointer misuse and no
 * arithmetic overflow. AES/CMAC are abstracted soundly (aes_stub.c).
 * Run: proofs/run_cbmc.sh */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../lib/scp03/scp03.c"      /* statics (take_tag1, xfer) become visible */

/* main.c's g0_read_mode_pcr TLV walk, verbatim */
static int mode_pcr_tlv_walk(const uint8_t *rsp, size_t rl, uint8_t out[32]) {
    size_t i = 0;
    while (i + 2 <= rl) {
        uint8_t tag = rsp[i++];
        size_t len = rsp[i++];
        if (len == 0x81) { if (i >= rl) break; len = rsp[i++]; }
        else if (len == 0x82) { if (i + 1 >= rl) break; len = ((size_t)rsp[i] << 8) | rsp[i+1]; i += 2; }
        if (i + len > rl) break;
        if (len == 32) { (void)tag; memcpy(out, rsp + i, 32); return 0; }
        i += len;
    }
    return -3;
}

/* The adversary: any response of any length the transport contract allows. */
static int adv_xfer(void *ctx, const uint8_t *apdu, size_t alen, uint8_t *rsp, size_t rcap, size_t *rlen) {
    (void)ctx;
    __CPROVER_assert(alen == 0 || __CPROVER_r_ok(apdu, alen), "apdu readable by transport");
    int fail; if (fail) return -1;
    size_t n; __CPROVER_assume(n <= rcap);
    for (size_t i = 0; i < n; i++) { uint8_t v; rsp[i] = v; }
    *rlen = n;
    return 0;
}

#ifdef PROOF_TAG1
int main(void) {
    uint8_t body[128]; size_t blen; __CPROVER_assume(blen <= sizeof body);
    uint8_t out[48]; size_t ocap; __CPROVER_assume(ocap <= sizeof out); size_t ol;
    take_tag1(body, blen, out, ocap, &ol);
    return 0;
}
#endif
#ifdef PROOF_TLV
int main(void) {
    uint8_t rsp[96]; size_t rl; __CPROVER_assume(rl <= sizeof rsp);
    uint8_t out[32];
    mode_pcr_tlv_walk(rsp, rl, out);
    return 0;
}
#endif
#ifdef PROOF_OPEN
int main(void) {
    scp03_session_t s; uint8_t kse[16], hc[8], cc[8];
    scp03_open(&s, adv_xfer, NULL, kse, 0x20000030u, hc, cc);
    scp03_wipe(&s);
    return 0;
}
#endif
#ifdef PROOF_CMD
int main(void) {
    scp03_session_t s; memset(&s, 0, sizeof s);
    s.xfer = adv_xfer; s.authed = 1; s.stage = SCP03_ST_AUTHED;
    uint8_t which;
    uint8_t blob[48], inner[32], body[96], out32[32]; size_t bl;
    uint8_t d[6 + 2 + 32] = { 0x41, 0x04, 0x20, 0x00, 0x00, 0x33, 0x43, 32 };
    switch (which & 7) {
    case 0: scp03_read_object(&s, 0x20000002u, blob, sizeof blob, &bl); break;
    case 1: scp03_cipher_oneshot(&s, 0x20000020u, 1, blob + 16, blob, inner); break;
    case 2: if (scp03_cmd(&s, 0x02, 0x00, 0x00, d, 6, 1, body, sizeof body, &bl) == SCP03_OK) mode_pcr_tlv_walk(body, bl, out32); break;
    case 3: scp03_cmd(&s, 0x01, 0x09, 0x00, d, sizeof d, 0, NULL, 0, NULL); break;
    case 4: scp03_cmd(&s, 0x01, 0x09, 0x00, d, 6, 0, NULL, 0, NULL); break;
    case 5: scp03_cmd(&s, 0x04, 0x00, 0x28, d, 6, 0, NULL, 0, NULL); break;
    default: scp03_close(&s); break;
    }
    scp03_wipe(&s);
    return 0;
}
#endif
