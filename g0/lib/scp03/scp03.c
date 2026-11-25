/* scp03.c — see scp03.h. Every byte layout here is taken from NXP Plug & Trust
 * (github.com/NXP/plug-and-trust, master, Sep 2026), not from memory:
 *   session wrap ......... se05x_tlv.c: se05x_Transform / se05x_Transform_scp
 *   outer Lc/Le .......... fsl_sss_se05x_apis.c: sss_se05x_channel_txnRaw
 *   IU / EA .............. fsl_sss_se05x_scp03.c: nxScp03_GP_InitializeUpdate,
 *                          nxScp03_GP_ExternalAuthenticate
 *   key derivation ....... nxScp03_HostLocal_CalculateSessionKeys,
 *                          nxScp03_setDerivationData
 *   encrypt / MAC / resp . nxScp03_Com.c: nxSCP03_Encrypt_CommandAPDU,
 *                          nxpSCP03_CalculateMac_CommandAPDU,
 *                          nxpSCP03_Decrypt_ResponseAPDU, *_Get_ResponseICV
 * Do not "simplify" a framing choice without re-reading that function: the
 * C-MAC covers the inner header and Lc, so host and applet must agree on
 * every byte of it. */
#include "scp03.h"
#include "aes128.h"
#include <string.h>

/* ---- SE05x / GP constants (se05x_enums.h, nxScp03_Const.h) -------------- */
#define SE_CLA               0x80
#define INS_MGMT             0x04
#define INS_PROCESS          0x05
#define INS_READ             0x02
#define INS_CRYPTO           0x03
#define P1_DEFAULT           0x00
#define P1_CIPHER            0x0E
#define P2_DEFAULT           0x00
#define P2_SESSION_CREATE    0x1B
#define P2_SESSION_CLOSE     0x1C
#define P2_ENCRYPT_ONESHOT   0x37
#define P2_DECRYPT_ONESHOT   0x38
#define TAG_SESSION_ID       0x10
#define TAG_1                0x41
#define TAG_2                0x42
#define TAG_3                0x43
#define TAG_4                0x44
#define CIPHER_AES_CBC_NOPAD 0x0D

#define CLA_GP               0x80
#define CLA_GP_SEC           0x04
#define INS_GP_INIT_UPDATE   0x50
#define INS_GP_EXT_AUTH      0x82
#define SECLVL_FULL          0x33   /* C-DEC, R-ENC, C-MAC, R-MAC */

#define DD_SENC   0x04
#define DD_SMAC   0x06
#define DD_SRMAC  0x07
#define DD_CARD_CRYPTOGRAM 0x00
#define DD_HOST_CRYPTOGRAM 0x01
#define DD_L_64   0x0040
#define DD_L_128  0x0080

#define MAC_LEN   8                 /* SCP_COMMAND_MAC_SIZE */
#define PAD_BYTE  0x80

/* One work area; the G0 is single-threaded and the host tests are too. */
static uint8_t s_tx[2 + SCP03_APDU_MAX];
static uint8_t s_rx[2 + SCP03_APDU_MAX];
static uint8_t s_inner[SCP03_APDU_MAX];
static uint8_t s_tmp[16 + 2 + SCP03_APDU_MAX];   /* MCV || data for CMACs */

static void wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }

/* ---- AES-128 CMAC, RFC 4493 -------------------------------------------- */
static void shl1(uint8_t *o, const uint8_t *i) {
    uint8_t c = 0;
    for (int k = 15; k >= 0; k--) { uint8_t n = (uint8_t)(i[k] >> 7); o[k] = (uint8_t)((i[k] << 1) | c); c = n; }
}
void aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t mlen, uint8_t mac[16]) {
    struct AES128_ctx a; AES128_init_ctx(&a, key);
    uint8_t L[16] = {0}, K1[16], K2[16], X[16] = {0}, last[16];
    AES128_ECB_encrypt(&a, L);
    shl1(K1, L); if (L[0] & 0x80) K1[15] ^= 0x87;
    shl1(K2, K1); if (K1[0] & 0x80) K2[15] ^= 0x87;
    size_t n = (mlen + 15) / 16; int full = (n && (mlen % 16 == 0));
    if (n == 0) n = 1;
    for (size_t b = 0; b + 1 < n; b++) {
        for (int k = 0; k < 16; k++) X[k] ^= msg[b * 16 + k];
        AES128_ECB_encrypt(&a, X);
    }
    memset(last, 0, 16);
    size_t off = (n - 1) * 16, rem = mlen - off;
    memcpy(last, msg + off, rem);
    if (full) { for (int k = 0; k < 16; k++) last[k] ^= K1[k]; }
    else      { last[rem] = 0x80; for (int k = 0; k < 16; k++) last[k] ^= K2[k]; }
    for (int k = 0; k < 16; k++) X[k] ^= last[k];
    AES128_ECB_encrypt(&a, X);
    memcpy(mac, X, 16);
    wipe(&a, sizeof a); wipe(K1, 16); wipe(K2, 16); wipe(L, 16); wipe(X, 16); wipe(last, 16);
}

/* CMAC(key, mcv || d) */
static void cmac_chained(const uint8_t key[16], const uint8_t mcv[16],
                         const uint8_t *d, size_t dlen, uint8_t mac[16]) {
    memcpy(s_tmp, mcv, 16); memcpy(s_tmp + 16, d, dlen);
    aes128_cmac(key, s_tmp, 16 + dlen, mac);
    wipe(s_tmp, 16 + dlen);
}

/* ---- transport helpers -------------------------------------------------- */
static int xfer(scp03_session_t *s, const uint8_t *apdu, size_t alen, size_t *rlen) {
    if (s->nxfer < 0xFF) s->nxfer++;
    int rc = s->xfer(s->xctx, apdu, alen, s_rx, sizeof s_rx, rlen);
    if (rc != 0 || *rlen < 2 || *rlen > sizeof s_rx) return SCP03_E_XFER;
    s->last_sw = (uint16_t)((s_rx[*rlen - 2] << 8) | s_rx[*rlen - 1]);
    return SCP03_OK;
}

/* Outer ProcessSessionCmd around an already-built inner APDU:
 *   80 05 00 00 [Lc] 10 08 sid 41 [len] inner [00 00 if hasle]
 * Lc is 1 byte when payload < 0xFF and !hasle, else 00 hi lo
 * (sss_se05x_channel_txnRaw). TAG_1 length is BER short/81/82
 * (se05x_Transform_scp). */
static size_t wrap_session(const uint8_t sid[8], const uint8_t *inner, size_t ilen, int hasle) {
    size_t payload = 2 + 8 + 1 + (ilen <= 0x7F ? 1 : (ilen <= 0xFF ? 2 : 3)) + ilen;
    size_t i = 0;
    s_tx[i++] = SE_CLA; s_tx[i++] = INS_PROCESS; s_tx[i++] = P1_DEFAULT; s_tx[i++] = P2_DEFAULT;
    if (payload < 0xFF && !hasle) s_tx[i++] = (uint8_t)payload;
    else { s_tx[i++] = 0x00; s_tx[i++] = (uint8_t)(payload >> 8); s_tx[i++] = (uint8_t)payload; }
    s_tx[i++] = TAG_SESSION_ID; s_tx[i++] = 8; memcpy(s_tx + i, sid, 8); i += 8;
    s_tx[i++] = TAG_1;
    if (ilen <= 0x7F) s_tx[i++] = (uint8_t)ilen;
    else if (ilen <= 0xFF) { s_tx[i++] = 0x81; s_tx[i++] = (uint8_t)ilen; }
    else { s_tx[i++] = 0x82; s_tx[i++] = (uint8_t)(ilen >> 8); s_tx[i++] = (uint8_t)ilen; }
    memcpy(s_tx + i, inner, ilen); i += ilen;
    if (hasle) { s_tx[i++] = 0x00; s_tx[i++] = 0x00; }
    return i;
}

/* Inner PLAIN APDU (pre-authentication): hdr [Lc] data. No Le, ever
 * (se05x_Transform never appends one inside a session). */
static size_t build_inner_plain(const uint8_t hdr[4], const uint8_t *d, size_t dlen, int hasle) {
    size_t i = 0; memcpy(s_inner, hdr, 4); i = 4;
    if (dlen) {
        if (dlen < 0xFF && !hasle) s_inner[i++] = (uint8_t)dlen;
        else { s_inner[i++] = 0x00; s_inner[i++] = (uint8_t)(dlen >> 8); s_inner[i++] = (uint8_t)dlen; }
        memcpy(s_inner + i, d, dlen); i += dlen;
    }
    return i;
}

static void ctr_inc(uint8_t c[16]) { for (int i = 15; i > 0; i--) { if (++c[i]) break; } }
static void ctr_dec(uint8_t c[16]) { for (int i = 15; i > 0; i--) { if (c[i]--) break; } }

/* ICV for a command = AES(S-ENC, ctr); for a response = AES(S-ENC, 80||ctr[1..]) */
static void icv(const uint8_t senc[16], const uint8_t ctr[16], int response, uint8_t out[16]) {
    struct AES128_ctx a; AES128_init_ctx(&a, senc);
    memcpy(out, ctr, 16); if (response) out[0] = PAD_BYTE;
    AES128_ECB_encrypt(&a, out); wipe(&a, sizeof a);
}

/* ---- session open --------------------------------------------------------- */
/* nxScp03_setDerivationData: 11 x 00, constant, 00, L(2), counter 01, context */
static void set_dd(uint8_t dd[32], uint8_t constant, uint16_t L,
                   const uint8_t hc[8], const uint8_t cc[8]) {
    memset(dd, 0, 11); dd[11] = constant; dd[12] = 0x00;
    dd[13] = (uint8_t)(L >> 8); dd[14] = (uint8_t)L; dd[15] = 0x01;
    memcpy(dd + 16, hc, 8); memcpy(dd + 24, cc, 8);
}

int scp03_open(scp03_session_t *s, scp03_xfer_fn xf, void *xctx,
               const uint8_t kse[16], uint32_t auth_obj,
               const uint8_t host_chal[8], uint8_t card_chal_out[8]) {
    size_t rlen; int rc;
    memset(s, 0, sizeof *s);
    s->xfer = xf; s->xctx = xctx;

    /* 1. CreateSession: 80 04 00 1B 06 41 04 id 0C  — plain, anonymous, Le 0x0C
     *    exactly as the ESP32's createSession() (proven on silicon). */
    {
        uint8_t a[12] = { SE_CLA, INS_MGMT, P1_DEFAULT, P2_SESSION_CREATE, 0x06, TAG_1, 0x04,
                          (uint8_t)(auth_obj >> 24), (uint8_t)(auth_obj >> 16),
                          (uint8_t)(auth_obj >> 8), (uint8_t)auth_obj, 0x0C };
        if ((rc = xfer(s, a, 12, &rlen)) != SCP03_OK) return rc;
        if (s->last_sw != 0x9000) return SCP03_E_SW;
        /* Body is TLV[TAG_1] = 8-byte session id, then SW. The applet may
         * encode the length short-form (41 08 ..) or BER extended-form
         * (41 82 00 08 ..) — SE051 7.2.0 uses the extended form here. Accept
         * both; take_tag1 already does the general parse. */
        {
            size_t off;
            if (rlen < 2 + 8 + 2 || s_rx[0] != TAG_1) return SCP03_E_FORMAT;
            if (s_rx[1] == 0x08) off = 2;
            else if (s_rx[1] == 0x81 && s_rx[2] == 0x08) off = 3;
            else if (s_rx[1] == 0x82 && s_rx[2] == 0x00 && s_rx[3] == 0x08) off = 4;
            else return SCP03_E_FORMAT;
            if (off + 8 + 2 != rlen) return SCP03_E_FORMAT;
            memcpy(s->sid, s_rx + off, 8);
        }
        s->stage = SCP03_ST_CREATED;
    }

    /* 2. INITIALIZE UPDATE, wrapped, plain. 80 50 <keyver 00> 00 08 hostchal — Case4,
     *    hasle=0 (nxScp03_GP_InitializeUpdate -> DoAPDUTxRx_s_Case4). */
    uint8_t cc[8], card_cryptogram[8];
    {
        static const uint8_t hdr[4] = { CLA_GP, INS_GP_INIT_UPDATE, 0x00, 0x00 };
        size_t il = build_inner_plain(hdr, host_chal, 8, 0);
        size_t ol = wrap_session(s->sid, s_inner, il, 0);
        if ((rc = xfer(s, s_tx, ol, &rlen)) != SCP03_OK) return rc;
        if (s->last_sw != 0x9000) return SCP03_E_SW;
        /* 10 key-div + 3 key-info + 8 card challenge + 8 card cryptogram [+3 seq] + SW */
        if (rlen != 31 && rlen != 34) return SCP03_E_FORMAT;
        memcpy(cc, s_rx + 13, 8);
        memcpy(card_cryptogram, s_rx + 21, 8);
        if (card_chal_out) memcpy(card_chal_out, cc, 8);
        s->stage = SCP03_ST_IU_DONE;
    }

    /* 3. session keys from the ONE static key (Enc = Mac = K_SE), then cryptograms */
    uint8_t dd[32], mac[16];
    set_dd(dd, DD_SENC,  DD_L_128, host_chal, cc); aes128_cmac(kse, dd, 32, s->senc);
    set_dd(dd, DD_SMAC,  DD_L_128, host_chal, cc); aes128_cmac(kse, dd, 32, s->smac);
    set_dd(dd, DD_SRMAC, DD_L_128, host_chal, cc); aes128_cmac(kse, dd, 32, s->srmac);
    set_dd(dd, DD_CARD_CRYPTOGRAM, DD_L_64, host_chal, cc); aes128_cmac(s->smac, dd, 32, mac);
    if (memcmp(mac, card_cryptogram, 8) != 0) {
        wipe(dd, 32); wipe(mac, 16); uint8_t st = s->stage; scp03_wipe(s); s->stage = st;
        return SCP03_E_CRYPTOGRAM;
    }
    s->stage = SCP03_ST_KEYS;
    uint8_t host_cryptogram[8];
    set_dd(dd, DD_HOST_CRYPTOGRAM, DD_L_64, host_chal, cc); aes128_cmac(s->smac, dd, 32, mac);
    memcpy(host_cryptogram, mac, 8);
    wipe(dd, 32);

    /* 4. EXTERNAL AUTHENTICATE: 84 82 33 00 10 hostcrypto8 mac8. MAC = CMAC(S-MAC,
     *    zero MCV || first 13 bytes) — Lc counts the MAC as already appended
     *    (SCP03 spec fig 6-1). Case3, hasle=0; CLA is already 0x84 so the plain
     *    wrap copies it unchanged. */
    {
        uint8_t ea[21] = { CLA_GP | CLA_GP_SEC, INS_GP_EXT_AUTH, SECLVL_FULL, 0x00, 0x10 };
        memcpy(ea + 5, host_cryptogram, 8);
        memset(s->mcv, 0, 16);
        cmac_chained(s->smac, s->mcv, ea, 13, mac);
        memcpy(s->mcv, mac, 16);
        memcpy(ea + 13, mac, 8);
        memcpy(s_inner, ea, 21);
        size_t ol = wrap_session(s->sid, s_inner, 21, 0);
        wipe(ea, 21); wipe(mac, 16); wipe(host_cryptogram, 8);
        rc = xfer(s, s_tx, ol, &rlen);
        if (rc != SCP03_OK || s->last_sw != 0x9000) {
            uint16_t sw = s->last_sw; uint8_t st = s->stage, n = s->nxfer;
            scp03_wipe(s); s->last_sw = sw; s->stage = st; s->nxfer = n;
            return rc != SCP03_OK ? rc : SCP03_E_SW;
        }
    }
    memset(s->ctr, 0, 16); s->ctr[15] = 0x01;
    s->authed = 1; s->stage = SCP03_ST_AUTHED;
    return SCP03_OK;
}

/* ---- encrypted command ---------------------------------------------------- */
int scp03_cmd(scp03_session_t *s, uint8_t ins, uint8_t p1, uint8_t p2,
              const uint8_t *data, size_t dlen, int hasle,
              uint8_t *out, size_t ocap, size_t *olen) {
    if (!s->authed) return SCP03_E_STATE;
    if (olen) *olen = 0;
    if (dlen + 16 + MAC_LEN + 8 > sizeof s_inner) return SCP03_E_SIZE;

    /* encrypt: pad 80 00.. to a block, CBC under S-ENC with ICV = AES(ctr).
     * An empty payload (CloseSession) is NOT padded or encrypted. */
    size_t elen = 0, i = 0;
    size_t lc;
    s_inner[i++] = SE_CLA | CLA_GP_SEC; s_inner[i++] = ins; s_inner[i++] = p1; s_inner[i++] = p2;
    if (dlen) {
        elen = dlen + 1; while (elen % 16) elen++;
        lc = elen + MAC_LEN;
        if (lc < 0xFF && !hasle) s_inner[i++] = (uint8_t)lc;
        else { s_inner[i++] = 0x00; s_inner[i++] = (uint8_t)(lc >> 8); s_inner[i++] = (uint8_t)lc; }
        uint8_t *ct = s_inner + i;
        memcpy(ct, data, dlen); ct[dlen] = PAD_BYTE; memset(ct + dlen + 1, 0, elen - dlen - 1);
        uint8_t iv[16]; icv(s->senc, s->ctr, 0, iv);
        struct AES128_ctx a; AES128_init_ctx_iv(&a, s->senc, iv);
        AES128_CBC_encrypt_buffer(&a, ct, elen);
        wipe(&a, sizeof a); wipe(iv, 16);
        i += elen;
    } else {
        lc = MAC_LEN;
        if (lc < 0xFF && !hasle) s_inner[i++] = (uint8_t)lc;
        else { s_inner[i++] = 0x00; s_inner[i++] = 0x00; s_inner[i++] = (uint8_t)lc; }
    }
    /* C-MAC over MCV || hdr|04 || Lc || ciphertext; new MCV = full 16; append 8 */
    uint8_t mac[16];
    cmac_chained(s->smac, s->mcv, s_inner, i, mac);
    memcpy(s->mcv, mac, 16);
    memcpy(s_inner + i, mac, MAC_LEN); i += MAC_LEN;
    wipe(mac, 16);

    size_t ol = wrap_session(s->sid, s_inner, i, hasle);
    wipe(s_inner, i);
    size_t rlen; int rc = xfer(s, s_tx, ol, &rlen);
    wipe(s_tx, ol);
    if (rc != SCP03_OK) return rc;

    /* The middleware bumps the counter on every answered command, 9000 or not
     * (se05x_DeCrypt else-branch / Decrypt_ResponseAPDU tail). */
    ctr_inc(s->ctr);
    if (s->last_sw != 0x9000) return SCP03_E_SW;

    /* response: [enc body] rmac8 SW — R-MAC = CMAC(S-RMAC, MCV || enc body || SW)[0..8].
     * A 9000 that arrives without an R-MAC is not something this session accepts. */
    if (rlen < MAC_LEN + 2) return SCP03_E_RMAC;
    size_t blen = rlen - MAC_LEN - 2;
    {
        size_t t = 0;
        memcpy(s_tmp, s->mcv, 16); t = 16;
        memcpy(s_tmp + t, s_rx, blen); t += blen;
        s_tmp[t++] = s_rx[rlen - 2]; s_tmp[t++] = s_rx[rlen - 1];
        aes128_cmac(s->srmac, s_tmp, t, mac);
        wipe(s_tmp, t);
        int bad = memcmp(mac, s_rx + blen, MAC_LEN) != 0;
        wipe(mac, 16);
        if (bad) return SCP03_E_RMAC;
    }
    if (blen == 0) return SCP03_OK;
    if (blen % 16) return SCP03_E_FORMAT;

    /* decrypt with ICV = AES(S-ENC, 80 || ctr[1..15]) where ctr is the value the
     * command went out under (we have already incremented, so step back). */
    uint8_t cmdctr[16]; memcpy(cmdctr, s->ctr, 16); ctr_dec(cmdctr);
    uint8_t iv[16]; icv(s->senc, cmdctr, 1, iv); wipe(cmdctr, 16);
    struct AES128_ctx a; AES128_init_ctx_iv(&a, s->senc, iv);
    AES128_CBC_decrypt_buffer(&a, s_rx, blen);
    wipe(&a, sizeof a); wipe(iv, 16);
    /* strip 80 00.. padding; must sit within the last block (RestoreSw_RAPDU) */
    size_t p = blen;
    while (p > 0 && p > blen - 16 && s_rx[p - 1] == 0x00) p--;
    if (p == 0 || s_rx[p - 1] != PAD_BYTE) { wipe(s_rx, blen); return SCP03_E_PAD; }
    p--;
    if (p > ocap) { wipe(s_rx, blen); return SCP03_E_SIZE; }
    memcpy(out, s_rx, p); if (olen) *olen = p;
    wipe(s_rx, blen);
    return SCP03_OK;
}

/* ---- wrappers ---------------------------------------------------------------- */
static size_t put_tlv(uint8_t *b, size_t i, uint8_t tag, const uint8_t *v, size_t n) {
    b[i++] = tag; b[i++] = (uint8_t)n; memcpy(b + i, v, n); return i + n;
}
static void put_u32(uint8_t o[4], uint32_t v) { o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16); o[2] = (uint8_t)(v >> 8); o[3] = (uint8_t)v; }

/* Body of a successful ReadObject / CipherOneShot is TLV[TAG_1] = data. */
static int take_tag1(const uint8_t *body, size_t blen, uint8_t *out, size_t ocap, size_t *olen) {
    if (blen < 2 || body[0] != TAG_1) return SCP03_E_FORMAT;
    size_t l, off;
    if (body[1] < 0x80) { l = body[1]; off = 2; }
    else if (body[1] == 0x81 && blen >= 3) { l = body[2]; off = 3; }
    else if (body[1] == 0x82 && blen >= 4) { l = ((size_t)body[2] << 8) | body[3]; off = 4; }
    else return SCP03_E_FORMAT;
    if (off + l > blen || l > ocap) return SCP03_E_FORMAT;
    memcpy(out, body + off, l); *olen = l;
    return SCP03_OK;
}

int scp03_read_object(scp03_session_t *s, uint32_t obj, uint8_t *out, size_t ocap, size_t *olen) {
    uint8_t id[4], d[6]; put_u32(id, obj);
    size_t n = put_tlv(d, 0, TAG_1, id, 4);            /* offset/length omitted = whole object */
    uint8_t body[128]; size_t bl;
    int rc = scp03_cmd(s, INS_READ, P1_DEFAULT, P2_DEFAULT, d, n, 1, body, sizeof body, &bl);
    if (rc != SCP03_OK) return rc;
    rc = take_tag1(body, bl, out, ocap, olen);
    wipe(body, sizeof body);
    return rc;
}

int scp03_cipher_oneshot(scp03_session_t *s, uint32_t key_obj, int decrypt,
                         const uint8_t in[32], const uint8_t iv[16], uint8_t out[32]) {
    uint8_t id[4], mode = CIPHER_AES_CBC_NOPAD, d[64]; put_u32(id, key_obj);
    size_t n = 0;
    n = put_tlv(d, n, TAG_1, id, 4);
    n = put_tlv(d, n, TAG_2, &mode, 1);
    n = put_tlv(d, n, TAG_3, in, 32);
    n = put_tlv(d, n, TAG_4, iv, 16);
    uint8_t body[64]; size_t bl, ol = 0;
    int rc = scp03_cmd(s, INS_CRYPTO, P1_CIPHER, decrypt ? P2_DECRYPT_ONESHOT : P2_ENCRYPT_ONESHOT,
                       d, n, 1, body, sizeof body, &bl);
    wipe(d, sizeof d);
    if (rc != SCP03_OK) return rc;
    rc = take_tag1(body, bl, out, 32, &ol);
    wipe(body, sizeof body);
    if (rc == SCP03_OK && ol != 32) rc = SCP03_E_FORMAT;
    return rc;
}

/* Restorable passkeys (30 Oct 2026). WriteECKey of a PRIVATE key alone over an
 * existing P-256 object: P1 = P1_PRIVATE | P1_EC, TAG_1 id, TAG_3 key, no curve
 * and no policy (both fixed at creation; re-sending the curve is 6A80 on this
 * SE, bench 2b/2d). Case3, no Le. The key travels only inside the session. */
int scp03_ec_write_priv(scp03_session_t *s, uint32_t obj, const uint8_t priv[32]) {
    uint8_t id[4], d[48]; put_u32(id, obj);
    size_t n = put_tlv(d, 0, TAG_1, id, 4);
    n = put_tlv(d, n, TAG_3, priv, 32);
    int rc = scp03_cmd(s, 0x01 /*INS_WRITE*/, 0x41 /*P1_PRIVATE|P1_EC*/, P2_DEFAULT, d, n, 0, NULL, 0, NULL);
    wipe(d, sizeof d);
    return rc;
}
/* ECDSA-SHA256 over a caller-supplied 32-byte hash with key object obj.
 * INS_CRYPTO, P1_SIGNATURE 0x0C, P2_SIGN 0x09, TAG_2 = SIG_ECDSA_SHA_256 0x21.
 * der receives the DER signature (<= 72 bytes for P-256). */
int scp03_ec_sign(scp03_session_t *s, uint32_t obj, const uint8_t hash[32],
                  uint8_t *der, size_t dcap, size_t *dlen) {
    uint8_t id[4], algo = 0x21, d[48]; put_u32(id, obj);
    size_t n = put_tlv(d, 0, TAG_1, id, 4);
    n = put_tlv(d, n, TAG_2, &algo, 1);
    n = put_tlv(d, n, TAG_3, hash, 32);
    uint8_t body[96]; size_t bl = 0;
    int rc = scp03_cmd(s, INS_CRYPTO, 0x0C, 0x09, d, n, 1, body, sizeof body, &bl);
    if (rc == SCP03_OK) rc = take_tag1(body, bl, der, dcap, dlen);
    if (rc == SCP03_OK && (*dlen < 8 || der[0] != 0x30)) rc = SCP03_E_FORMAT;
    wipe(body, sizeof body);
    return rc;
}

int scp03_close(scp03_session_t *s) {
    int rc = SCP03_E_STATE;
    if (s->authed) rc = scp03_cmd(s, INS_MGMT, P1_DEFAULT, P2_SESSION_CLOSE, NULL, 0, 0, NULL, 0, NULL);
    uint16_t sw = s->last_sw; uint8_t n = s->nxfer;
    scp03_wipe(s);
    s->last_sw = sw; s->nxfer = n; s->stage = SCP03_ST_CLOSED;
    return rc;
}

void scp03_wipe(scp03_session_t *s) {
    scp03_xfer_fn xf = s->xfer; void *xc = s->xctx;
    wipe(s, sizeof *s);
    s->xfer = xf; s->xctx = xc;
    wipe(s_tx, sizeof s_tx); wipe(s_rx, sizeof s_rx); wipe(s_inner, sizeof s_inner); wipe(s_tmp, sizeof s_tmp);
}
