/* fuzz_scp03.c — libFuzzer harness for lib/scp03 (the G0's SE-response parser)
 * and the MODE_PCR TLV walker from main.c.
 *
 * The threat: an RCE'd ESP32 is the relay, so every R-APDU the G0 sees is
 * attacker-controlled. This harness plays that ESP32/SE: the fuzz input is a
 * stream of responses, one per xfer() call. Control bits let the "card" side
 * be honest at each layer so the deeper parsers get reached:
 *   - IU response: optionally patch in the CORRECT card cryptogram (the
 *     harness knows K_SE + host challenge), so scp03_open reaches EA/AUTHED
 *   - encrypted commands: optionally wrap the fuzz body in a valid R-MAC, and
 *     optionally encrypt it properly (so the pad check and take_tag1 /
 *     g0_read_mode_pcr see arbitrary PLAINTEXT), or hand over garbage
 * Everything the code does with those bytes runs under ASan + UBSan.
 *
 * Build/run: tests/run_fuzz_scp03.sh
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "scp03.h"
#include "aes128.h"

/* ---- copy of main.c's g0_read_mode_pcr TLV walk (static there) --------- */
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

/* ---- fuzz stream ------------------------------------------------------- */
typedef struct {
    const uint8_t *d; size_t n, pos;
    scp03_session_t *s;
    uint8_t kse[16], hc[8];
    int n_calls;
} fz_t;

static int take_byte(fz_t *f, uint8_t *b) { if (f->pos >= f->n) return 0; *b = f->d[f->pos++]; return 1; }

/* SCP03 KDF pieces, duplicated so the harness can be an honest card */
static void set_dd(uint8_t dd[32], uint8_t constant, uint16_t L, const uint8_t hc[8], const uint8_t cc[8]) {
    memset(dd, 0, 11); dd[11] = constant; dd[12] = 0x00;
    dd[13] = (uint8_t)(L >> 8); dd[14] = (uint8_t)L; dd[15] = 0x01;
    memcpy(dd + 16, hc, 8); memcpy(dd + 24, cc, 8);
}

static int fz_xfer(void *ctx, const uint8_t *apdu, size_t alen, uint8_t *rsp, size_t rcap, size_t *rlen) {
    (void)apdu; (void)alen;
    fz_t *f = (fz_t *)ctx;
    f->n_calls++;
    uint8_t ctl, l0, l1;
    if (!take_byte(f, &ctl)) return -1;                 /* transport failure */
    if (!take_byte(f, &l0)) return -1;
    if (!take_byte(f, &l1)) return -1;
    size_t want = ((size_t)l1 << 8 | l0) % (rcap + 1); /* 0..rcap, any length allowed */
    size_t have = f->n - f->pos; if (want > have) want = have;
    memcpy(rsp, f->d + f->pos, want); f->pos += want;
    *rlen = want;

    scp03_session_t *s = f->s;
    /* Honest-card patches, per control bits. Applied AFTER the fuzz bytes so
     * the fuzzer can still break any field it likes. */
    if ((ctl & 0x01) && *rlen >= 2) { rsp[*rlen - 2] = 0x90; rsp[*rlen - 1] = 0x00; }   /* SW 9000 */

    if ((ctl & 0x02) && s->stage == SCP03_ST_CREATED) {
        /* IU response: make it 31 bytes with a correct card cryptogram */
        uint8_t iu[31]; memset(iu, 0, sizeof iu);
        memcpy(iu, rsp, *rlen < 29 ? *rlen : 29);
        uint8_t cc[8]; memcpy(cc, iu + 13, 8);
        uint8_t dd[32], smac[16], mac[16];
        set_dd(dd, 0x06 /*DD_SMAC*/, 0x0080, f->hc, cc); aes128_cmac(f->kse, dd, 32, smac);
        set_dd(dd, 0x00 /*DD_CARD_CRYPTOGRAM*/, 0x0040, f->hc, cc); aes128_cmac(smac, dd, 32, mac);
        memcpy(iu + 21, mac, 8);
        iu[29] = 0x90; iu[30] = 0x00;
        memcpy(rsp, iu, 31); *rlen = 31;
    }

    if ((ctl & 0x04) && s->authed) {
        /* Encrypted command response: body || RMAC8 || SW, body a multiple of
         * 16. ctl&0x08: encrypt the fuzz bytes as PLAINTEXT with 80-padding
         * (so the parsers past the pad check see them); else use them raw. */
        size_t body = *rlen; if (body > 2) body -= 2; else body = 0;
        uint8_t plain[SCP03_APDU_MAX]; size_t pl = body;
        if (pl > 480) pl = 480;
        memcpy(plain, rsp, pl);
        size_t elen = 0;
        if (ctl & 0x08) {
            if (pl) { elen = pl + 1; while (elen % 16) elen++; plain[pl] = 0x80; memset(plain + pl + 1, 0, elen - pl - 1); }
            uint8_t iv[16]; memcpy(iv, s->ctr, 16); iv[0] = 0x80;
            struct AES128_ctx a; AES128_init_ctx(&a, s->senc); AES128_ECB_encrypt(&a, iv);
            AES128_init_ctx_iv(&a, s->senc, iv);
            if (elen) AES128_CBC_encrypt_buffer(&a, plain, elen);
        } else {
            elen = pl - (pl % 16);
        }
        uint8_t sw[2] = { 0x90, 0x00 };
        if (!(ctl & 0x01) && *rlen >= 2) { sw[0] = rsp[*rlen-2]; sw[1] = rsp[*rlen-1]; }
        uint8_t tmp[16 + SCP03_APDU_MAX + 2]; size_t t = 0;
        memcpy(tmp, s->mcv, 16); t = 16; memcpy(tmp + t, plain, elen); t += elen; tmp[t++] = sw[0]; tmp[t++] = sw[1];
        uint8_t mac[16]; aes128_cmac(s->srmac, tmp, t, mac);
        memcpy(rsp, plain, elen); memcpy(rsp + elen, mac, 8); rsp[elen + 8] = sw[0]; rsp[elen + 9] = sw[1];
        *rlen = elen + 10;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    fz_t f; memset(&f, 0, sizeof f);
    f.d = data; f.n = size; f.pos = 0;
    for (int i = 0; i < 16; i++) f.kse[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 8; i++) f.hc[i] = (uint8_t)(0xA0 + i);
    scp03_session_t s; memset(&s, 0, sizeof s); f.s = &s;
    uint8_t cc[8];
    int rc = scp03_open(&s, fz_xfer, &f, f.kse, 0x20000030u, f.hc, cc);
    if (rc == SCP03_OK) {
        /* the exact command mix the G0 issues, in the orders it issues them */
        uint8_t plan; if (!take_byte(&f, &plan)) plan = 0;
        uint8_t blob[48], inner[32], out32[32], body[96]; size_t bl = 0;
        for (int step = 0; step < 6; step++) {
            switch ((plan >> (step & 3)) & 3) {
            case 0: scp03_read_object(&s, 0x20000002u, blob, sizeof blob, &bl); break;
            case 1: scp03_cipher_oneshot(&s, 0x20000020u, 1, blob + 16, blob, inner); break;
            case 2: {   /* MODE_PCR read + the main.c TLV walk over the decrypted body */
                uint32_t oid = 0x20000033u;
                uint8_t d[6] = { 0x41, 0x04, (uint8_t)(oid >> 24), (uint8_t)(oid >> 16), (uint8_t)(oid >> 8), (uint8_t)oid };
                bl = 0;
                if (scp03_cmd(&s, 0x02, 0x00, 0x00, d, 6, 1, body, sizeof body, &bl) == SCP03_OK) mode_pcr_tlv_walk(body, bl, out32);
                break; }
            case 3: {   /* WritePCR extend / reset (no Le) */
                uint8_t d[6 + 2 + 32] = { 0x41, 0x04, 0x20, 0x00, 0x00, 0x33, 0x43, 32 };
                scp03_cmd(&s, 0x01, 0x09, 0x00, d, (step & 1) ? sizeof d : 6, 0, NULL, 0, NULL);
                break; }
            }
            if (!s.authed) break;
        }
        scp03_close(&s);
    }
    scp03_wipe(&s);
    return 0;
}
