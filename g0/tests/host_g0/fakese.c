/* Fake SE051 for the G0 host harness (audit 21 Nov 2026).
 * Replaces lib/scp03: scp03_open/cmd/... talk straight to an in-memory SE
 * that holds objects and enforces the policies the ESP32 code gives them
 * (se_signer.cpp, mode_pcr.inc), as far as the G0's commands reach. The
 * harness (the "ESP32") uses fse_* below for its own PIN-session and
 * anonymous operations. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "scp03.h"
#include "sha256.h"
#include "fakese.h"

fse_obj_t fse[FSE_MAX];
int fse_log = 0;
static uint32_t sess_principal[1];   /* one SE session at a time, as the silicon */

fse_obj_t *fse_find(uint32_t id) {
    for (int i = 0; i < FSE_MAX; i++) if (fse[i].used && fse[i].id == id) return &fse[i];
    return NULL;
}
fse_obj_t *fse_create(uint32_t id, int kind) {
    if (fse_find(id)) return NULL;   /* an id in use cannot be created again */
    for (int i = 0; i < FSE_MAX; i++) if (!fse[i].used) {
        memset(&fse[i], 0, sizeof fse[i]); fse[i].used = 1; fse[i].id = id; fse[i].kind = kind; return &fse[i];
    }
    return NULL;
}
void fse_neutral(uint8_t out[32]) { uint8_t z[32] = {0}; sha256(z, 32, out); }
void fse_ext(const uint8_t cur[32], const uint8_t e[32], uint8_t out[32]) { uint8_t b[64]; memcpy(b, cur, 32); memcpy(b + 32, e, 32); sha256(b, 64, out); }

/* rights of principal p on object o (FSE_R_*), honouring a PCR gate */
uint32_t fse_rights(const fse_obj_t *o, uint32_t p) {
    uint32_t r = 0;
    for (int i = 0; i < o->npol; i++) {
        const fse_pol_t *e = &o->pol[i];
        if (e->who != p) continue;
        if (e->gate_pcr) {
            const fse_obj_t *g = fse_find(e->gate_pcr);
            if (!g || memcmp(g->val, e->gate_val, 32) != 0) continue;
        }
        r = e->rights; break;   /* silicon: only the FIRST entry for an auth object counts */
    }
    if (o->npol == 0) r = 0xFFFFFFFFu;   /* no policy: anyone */
    return r;
}

static int sw_err(scp03_session_t *s, uint16_t sw) { s->last_sw = sw; return SCP03_E_SW; }
static int sw_ok(scp03_session_t *s) { s->last_sw = 0x9000; return SCP03_OK; }

int scp03_open(scp03_session_t *s, scp03_xfer_fn xfer, void *xctx, const uint8_t key[16],
               uint32_t auth, const uint8_t hc[8], uint8_t cc[8]) {
    (void)xfer; (void)xctx; (void)hc;
    memset(s, 0, sizeof(*s));
    if (cc) for (int i = 0; i < 8; i++) cc[i] = (uint8_t)(0x30 + i);
    fse_obj_t *a = fse_find(auth);
    if (!a || a->kind != FSE_K_AUTH) { s->stage = 0; s->last_sw = 0x6A88; return SCP03_E_SW; }
    if (memcmp(a->val, key, 16) != 0) { s->stage = 3; return SCP03_E_CRYPTOGRAM; }
    s->stage = 4; s->authed = 1; s->nxfer = 4;
    sess_principal[0] = auth; memcpy(s->sid, &auth, 4);
    return SCP03_OK;
}
static uint32_t principal(scp03_session_t *s) { uint32_t p; memcpy(&p, s->sid, 4); return p; }
static uint32_t rd_id(const uint8_t *d, size_t n) {
    if (n < 6 || d[0] != 0x41 || d[1] != 0x04) return 0;
    return ((uint32_t)d[2] << 24) | ((uint32_t)d[3] << 16) | ((uint32_t)d[4] << 8) | d[5];
}
int scp03_cmd(scp03_session_t *s, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *d, size_t dl,
              int hasle, uint8_t *out, size_t ocap, size_t *olen) {
    (void)hasle;
    if (!s->authed) return SCP03_E_STATE;
    s->nxfer++;
    uint32_t P = principal(s), id = rd_id(d, dl);
    fse_obj_t *o = id ? fse_find(id) : NULL;
    if (olen) *olen = 0;
    if (ins == 0x01 && p1 == 0x09) {                 /* WritePCR: extend (TAG_3) or reset (TAG_1 only) */
        if (!o) return sw_err(s, 0x6A88);
        if (o->kind != FSE_K_PCR) return sw_err(s, 0x6985);
        uint32_t r = fse_rights(o, P);
        if (dl >= 6 + 2 + 32 && d[6] == 0x43 && d[7] == 32) {
            if (!(r & FSE_R_WRITE)) return sw_err(s, 0x6986);
            fse_ext(o->val, d + 8, o->val); o->reset_base = 0;
            if (fse_log) printf("    SE: %08X extends PCR %08X\n", P, id);
            return sw_ok(s);
        }
        if (!(r & FSE_R_DELETE)) return sw_err(s, 0x6986);
        uint8_t n[32]; fse_neutral(n);
        if (memcmp(o->val, n, 32) == 0) return sw_err(s, 0x6985);   /* silicon: reset at initial is refused */
        memcpy(o->val, n, 32);
        if (fse_log) printf("    SE: %08X resets PCR %08X\n", P, id);
        return sw_ok(s);
    }
    if (ins == 0x02) {                               /* ReadObject */
        if (!o) return sw_err(s, 0x6A88);
        if (!(fse_rights(o, P) & FSE_R_READ)) return sw_err(s, 0x6986);
        size_t n = o->kind == FSE_K_PCR ? 32 : o->len;
        if (!out || ocap < n + 2) return SCP03_E_SIZE;
        out[0] = 0x41; out[1] = (uint8_t)n; memcpy(out + 2, o->val, n); *olen = n + 2;
        return sw_ok(s);
    }
    if (ins == 0x04 && p2 == 0x28) {                 /* DeleteSecureObject */
        if (!o) return sw_err(s, 0x6985);            /* silicon fact: absent answers 6985 */
        if (!(fse_rights(o, P) & FSE_R_DELETE)) return sw_err(s, 0x6986);
        if (fse_log) printf("    SE: %08X deletes %08X\n", P, id);
        o->used = 0;
        return sw_ok(s);
    }
    if (ins == 0x04 && p2 == 0x27) {                 /* CheckObjectExists */
        if (!out || ocap < 3) return SCP03_E_SIZE;
        out[0] = 0x41; out[1] = 0x01; out[2] = o ? 0x01 : 0x02; *olen = 3;
        return sw_ok(s);
    }
    if (ins == 0x01 && p1 == 0x41) {                 /* private EC key write over an existing object */
        if (!o) return sw_err(s, 0x6A88);
        if (!(fse_rights(o, P) & FSE_R_WRITE)) return sw_err(s, 0x6986);
        return sw_ok(s);
    }
    return sw_err(s, 0x6D00);
}
int scp03_read_object(scp03_session_t *s, uint32_t obj, uint8_t *out, size_t ocap, size_t *olen) {
    uint8_t d[6] = { 0x41, 0x04, (uint8_t)(obj >> 24), (uint8_t)(obj >> 16), (uint8_t)(obj >> 8), (uint8_t)obj };
    uint8_t b[300]; size_t bl = 0;
    int rc = scp03_cmd(s, 0x02, 0, 0, d, 6, 1, b, sizeof b, &bl);
    if (rc) return rc;
    if (bl - 2 > ocap) return SCP03_E_SIZE;
    memcpy(out, b + 2, bl - 2); *olen = bl - 2;
    return SCP03_OK;
}
/* the fake cipher: out = in XOR SHA256(key || iv); ENC and DEC alike */
void fse_crypt(const fse_obj_t *k, const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]) {
    uint8_t b[48], h[32]; memcpy(b, k->val, 32); memcpy(b + 32, iv, 16); sha256(b, 48, h);
    for (int i = 0; i < 32; i++) out[i] = in[i] ^ h[i];
}
int fse_cipher(uint32_t P, uint32_t key, int decrypt, const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]) {
    fse_obj_t *k = fse_find(key);
    if (!k || k->kind != FSE_K_AES) return 0x6A88;
    if (!(fse_rights(k, P) & (decrypt ? FSE_R_DEC : FSE_R_ENC))) return 0x6986;
    fse_crypt(k, in, iv, out);
    return 0x9000;
}
int scp03_cipher_oneshot(scp03_session_t *s, uint32_t key_obj, int decrypt, const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]) {
    if (!s->authed) return SCP03_E_STATE;
    int sw = fse_cipher(principal(s), key_obj, decrypt, in, iv, out);
    if (sw != 0x9000) return sw_err(s, (uint16_t)sw);
    return sw_ok(s);
}
int scp03_ec_write_priv(scp03_session_t *s, uint32_t obj, const uint8_t priv[32]) {
    (void)priv; uint8_t d[6] = { 0x41, 0x04, (uint8_t)(obj >> 24), (uint8_t)(obj >> 16), (uint8_t)(obj >> 8), (uint8_t)obj };
    return scp03_cmd(s, 0x01, 0x41, 0, d, 6, 0, NULL, 0, NULL);
}
int scp03_ec_sign(scp03_session_t *s, uint32_t obj, const uint8_t hash[32], uint8_t *der, size_t dcap, size_t *dlen) {
    (void)s; (void)obj; (void)hash; (void)der; (void)dcap; *dlen = 0; return SCP03_E_SW;
}
int scp03_close(scp03_session_t *s) { int ok = s->authed; memset(s, 0, sizeof(*s)); s->last_sw = 0x9000; return ok ? SCP03_OK : SCP03_E_STATE; }
void scp03_wipe(scp03_session_t *s) { memset(s, 0, sizeof(*s)); }
void aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t mlen, uint8_t mac[16]) { (void)key; (void)msg; (void)mlen; memset(mac, 0, 16); }
