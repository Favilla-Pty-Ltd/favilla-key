/* btc.c — see btc.h. BIP-32 / BIP-143 / ECDSA on libsecp256k1 for the G0.
 * Host-verified against embit (tests/host_btc.c): BIP-32 TV1+TV2, the BIP-143
 * P2WPKH native vector, and randomised P2WPKH/P2WSH requests. */
#include "btc.h"
#include "sha256.h"
#include "sha512.h"
#include "ripemd160.h"
#include "secp256k1_recovery.h"
#include <string.h>

static void wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

static int pub33_of(const secp256k1_context *ctx, const uint8_t priv[32], uint8_t pub33[33]) {
    secp256k1_pubkey pk; size_t l = 33;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, priv)) return -1;
    if (!secp256k1_ec_pubkey_serialize(ctx, pub33, &l, &pk, SECP256K1_EC_COMPRESSED) || l != 33) return -1;
    return 0;
}

static int master_from_seed(const uint8_t seed[64], btc_xprv *m) {
    uint8_t I[64];
    hmac_sha512((const uint8_t *)"Bitcoin seed", 12, seed, 64, I);
    memcpy(m->key, I, 32); memcpy(m->cc, I + 32, 32);
    wipe(I, 64);
    return 0;   /* IL validity is checked by the first tweak / pubkey op below */
}

/* CKDpriv. Hardened: HMAC(cc, 0x00 || k || i). Normal: HMAC(cc, pub33 || i).
 * child = (IL + k) mod n, refused if IL >= n or child == 0 (tweak_add does both). */
static int ckd_priv(const secp256k1_context *ctx, const btc_xprv *p, uint32_t i, btc_xprv *c) {
    uint8_t data[37], I[64]; int rc = -1;
    if (i & 0x80000000u) { data[0] = 0x00; memcpy(data + 1, p->key, 32); }
    else if (pub33_of(ctx, p->key, data) != 0) return -1;
    wr32be(data + 33, i);
    hmac_sha512(p->cc, 32, data, 37, I);
    memcpy(c->key, p->key, 32);
    if (secp256k1_ec_seckey_tweak_add(ctx, c->key, I)) { memcpy(c->cc, I + 32, 32); rc = 0; }
    else wipe(c, sizeof(*c));
    wipe(data, sizeof(data)); wipe(I, 64);
    return rc;
}

static int fp_of(const secp256k1_context *ctx, const uint8_t priv[32], uint8_t fp[4]) {
    uint8_t pub[33], h[20];
    if (pub33_of(ctx, priv, pub) != 0) return -1;
    hash160(pub, 33, h); memcpy(fp, h, 4);
    wipe(pub, 33); wipe(h, 20);
    return 0;
}

int btc_account(const secp256k1_context *ctx, const uint8_t seed[64], int purpose,
                btc_xprv *acct, uint8_t master_fp[4], uint8_t parent_fp[4]) {
    btc_xprv a, b; int rc = -1;
    const uint32_t H = 0x80000000u;
    if (master_from_seed(seed, &a) != 0) goto out;
    if (master_fp && fp_of(ctx, a.key, master_fp) != 0) goto out;
    if (purpose == 84) {
        /* m/84'/0'/0' : parent of the account = m/84'/0' */
        if (ckd_priv(ctx, &a, H + 84, &b) != 0) goto out;
        if (ckd_priv(ctx, &b, H + 0, &a) != 0) goto out;
        if (parent_fp && fp_of(ctx, a.key, parent_fp) != 0) goto out;
        if (ckd_priv(ctx, &a, H + 0, acct) != 0) goto out;
    } else if (purpose == 48) {
        /* m/48'/0'/0'/2' : parent of the account = m/48'/0'/0' */
        if (ckd_priv(ctx, &a, H + 48, &b) != 0) goto out;
        if (ckd_priv(ctx, &b, H + 0, &a) != 0) goto out;
        if (ckd_priv(ctx, &a, H + 0, &b) != 0) goto out;
        if (parent_fp && fp_of(ctx, b.key, parent_fp) != 0) goto out;
        if (ckd_priv(ctx, &b, H + 2, acct) != 0) goto out;
    } else goto out;
    rc = 0;
out:
    wipe(&a, sizeof(a)); wipe(&b, sizeof(b));
    if (rc) wipe(acct, sizeof(*acct));
    return rc;
}

int btc_leaf(const secp256k1_context *ctx, const btc_xprv *acct, uint32_t change, uint32_t index,
             uint8_t key[32], uint8_t pub33[33]) {
    btc_xprv ch, leaf; int rc = -1;
    if (change > 1 || (index & 0x80000000u)) return -1;
    if (ckd_priv(ctx, acct, change, &ch) == 0 && ckd_priv(ctx, &ch, index, &leaf) == 0 && pub33_of(ctx, leaf.key, pub33) == 0) {
        memcpy(key, leaf.key, 32); rc = 0;
    }
    wipe(&ch, sizeof(ch)); wipe(&leaf, sizeof(leaf));
    return rc;
}

int btc_xpub_of(const secp256k1_context *ctx, const btc_xprv *x, const uint8_t parent_fp[4], btc_xpub_t *out) {
    if (pub33_of(ctx, x->key, out->pub) != 0) return -1;
    memcpy(out->cc, x->cc, 32); memcpy(out->parent_fp, parent_fp, 4);
    return 0;
}

/* BIP-143 preimage:
 *   nVersion | hashPrevouts | hashSequence | outpoint | scriptCode(varint+script)
 *   | amount | nSequence | hashOutputs | nLockTime | sighash_type(4)
 * double-SHA256'd. scriptCode: P2WPKH = 19 76 a9 14 <pkh20> 88 ac (26 bytes with
 * the 0x19 length prefix); P2WSH = varint(len) || witnessScript. */
static void bip143_sighash(const uint8_t req[BTC_REQ_LEN], const uint8_t *scriptcode, size_t sclen, uint8_t out[32]) {
    sha256_ctx c; uint8_t t[32]; uint8_t st[4] = { req[1], 0, 0, 0 };
    sha256_init(&c);
    sha256_update(&c, req + 4, 4);      /* nVersion */
    sha256_update(&c, req + 12, 32);    /* hashPrevouts */
    sha256_update(&c, req + 44, 32);    /* hashSequence */
    sha256_update(&c, req + 108, 36);   /* outpoint */
    sha256_update(&c, scriptcode, sclen);
    sha256_update(&c, req + 148, 8);    /* amount */
    sha256_update(&c, req + 144, 4);    /* nSequence */
    sha256_update(&c, req + 76, 32);    /* hashOutputs */
    sha256_update(&c, req + 8, 4);      /* nLockTime */
    sha256_update(&c, st, 4);           /* sighash type, 4 bytes LE */
    sha256_final(&c, t);
    sha256(t, 32, out);
    wipe(t, 32);
}

/* ── signing, split for anti-exfil (27 Oct 2026) ─────────────────────────────
 * prepare: everything that needs the seed (validation, derivation, sighash or
 * digest) and nothing that needs a nonce. The seed is wiped by the caller as
 * soon as this returns; only the 32-byte leaf key lives on, in the pending
 * anti-exfil state, until FINISH or the 10 s timeout.
 * release: the verify-before-release checks of 19 Oct 2026 (re-derive the leaf
 * pubkey, require it to equal the one computed before signing, verify the
 * signature against it) and the serialisation. The nonce itself is chosen in
 * src/antiexfil.c and never here. */
int btc_sign_prepare(const secp256k1_context *ctx, const uint8_t seed[64],
                     const uint8_t req[BTC_REQ_LEN],
                     uint8_t leaf_key[32], uint8_t pub33[33], uint8_t sighash32[32]) {
    btc_xprv acct, ch, leaf; int rc = -1;
    uint8_t sc[3 + BTC_WS_MAX]; size_t scl = 0;
    const uint8_t kind = req[0];
    const uint32_t wslen = (uint32_t)req[2] | ((uint32_t)req[3] << 8);
    const uint32_t change = rd32(req + 156), index = rd32(req + 160);

    memset(&acct, 0, sizeof(acct)); memset(&ch, 0, sizeof(ch)); memset(&leaf, 0, sizeof(leaf));
    if (req[1] != BTC_SIGHASH_ALL) return -1;
    if (change > 1 || (index & 0x80000000u)) return -1;
    if (kind == BTC_KIND_P2WPKH) { if (wslen != 0) return -1; }
    else if (kind == BTC_KIND_P2WSH) { if (wslen == 0 || wslen > BTC_WS_MAX) return -1; }
    else return -1;

    /* fingerprints skipped (NULL): two fewer ~200 ms pubkey ops per signature */
    if (btc_account(ctx, seed, kind == BTC_KIND_P2WPKH ? 84 : 48, &acct, NULL, NULL) != 0) { rc = -2; goto out; }
    if (ckd_priv(ctx, &acct, change, &ch) != 0)  { rc = -2; goto out; }
    if (ckd_priv(ctx, &ch, index, &leaf) != 0)   { rc = -2; goto out; }
    if (pub33_of(ctx, leaf.key, pub33) != 0)     { rc = -2; goto out; }

    if (kind == BTC_KIND_P2WPKH) {
        uint8_t pkh[20]; hash160(pub33, 33, pkh);
        sc[0] = 0x19; sc[1] = 0x76; sc[2] = 0xa9; sc[3] = 0x14; memcpy(sc + 4, pkh, 20); sc[24] = 0x88; sc[25] = 0xac;
        scl = 26;
    } else {
        /* varint(len): 1 byte below 0xfd, else fd + LE16 */
        if (wslen < 0xfd) { sc[0] = (uint8_t)wslen; scl = 1; }
        else { sc[0] = 0xfd; sc[1] = (uint8_t)wslen; sc[2] = (uint8_t)(wslen >> 8); scl = 3; }
        memcpy(sc + scl, req + 164, wslen); scl += wslen;
    }
    bip143_sighash(req, sc, scl, sighash32);
    memcpy(leaf_key, leaf.key, 32);
    rc = 0;
out:
    wipe(&acct, sizeof(acct)); wipe(&ch, sizeof(ch)); wipe(&leaf, sizeof(leaf)); wipe(sc, sizeof(sc));
    if (rc) { wipe(pub33, 33); wipe(sighash32, 32); wipe(leaf_key, 32); }
    return rc;
}

int btc_sign_release(const secp256k1_context *ctx, const uint8_t leaf_key[32],
                     const uint8_t sighash32[32], const uint8_t pub33[33],
                     const secp256k1_ecdsa_signature *sig,
                     uint8_t der[BTC_DER_MAX], uint8_t *der_len) {
    size_t dl = BTC_DER_MAX; int rc = -3;
    /* 19 Oct 2026 (fault hardening): before release, re-derive the leaf pubkey
     * from the key, require it to equal the one computed before signing, and
     * verify the signature against it. Catches a glitched signature and a key
     * bit flipped between derivation and signing (which would give a valid
     * signature for the wrong key). ~0.4 s. */
    { uint8_t pub33b[33]; secp256k1_pubkey vpk; int good;
      good = pub33_of(ctx, leaf_key, pub33b) == 0 && memcmp(pub33b, pub33, 33) == 0 &&
             secp256k1_ec_pubkey_parse(ctx, &vpk, pub33, 33) &&
             secp256k1_ecdsa_verify(ctx, sig, sighash32, &vpk);
      wipe(pub33b, 33);
      if (!good) goto out; }
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &dl, sig) || dl > BTC_DER_MAX) { rc = -4; goto out; }
    *der_len = (uint8_t)dl;
    rc = 0;
out:
    if (rc) { wipe(der, BTC_DER_MAX); *der_len = 0; }
    return rc;
}

int btc_msg_request_valid(const uint8_t req[BTC_REQ_LEN]) {
    if (req[0] != 'F' || req[1] != 'M' || req[2] != 'S' || req[3] != 'G' || req[4] != 1) return 0;
    const uint32_t change = req[5], index = rd32(req + 6), len = req[10];
    if (change > 1 || (index & 0x80000000u)) return 0;
    if (len < 1 || len > BTC_MSG_MAX) return 0;
    for (uint32_t i = 0; i < len; i++) if (req[11 + i] < 0x20 || req[11 + i] > 0x7E) return 0;
    for (uint32_t i = 11 + len; i < BTC_REQ_LEN; i++) if (req[i] != 0) return 0;   /* no hidden tail */
    return 1;
}

int btc_msg_prepare(const secp256k1_context *ctx, const uint8_t seed[64],
                    const uint8_t req[BTC_REQ_LEN],
                    uint8_t leaf_key[32], uint8_t pub33[33], uint8_t digest32[32]) {
    static const uint8_t PREFIX[] = "\x18" "Bitcoin Signed Message:\n";   /* 25 bytes */
    btc_xprv acct, ch, leaf; int rc = -1;
    memset(&acct, 0, sizeof(acct)); memset(&ch, 0, sizeof(ch)); memset(&leaf, 0, sizeof(leaf));
    if (!btc_msg_request_valid(req)) return -1;
    const uint32_t change = req[5], index = rd32(req + 6), len = req[10];

    {   sha256_ctx c; uint8_t t[32], vl = (uint8_t)len;   /* len <= 240 < 0xfd: 1-byte varint */
        sha256_init(&c);
        sha256_update(&c, PREFIX, sizeof(PREFIX) - 1);
        sha256_update(&c, &vl, 1);
        sha256_update(&c, req + 11, len);
        sha256_final(&c, t);
        sha256(t, 32, digest32);
        wipe(t, 32); }

    if (btc_account(ctx, seed, 84, &acct, NULL, NULL) != 0) { rc = -2; goto out; }
    if (ckd_priv(ctx, &acct, change, &ch) != 0)  { rc = -2; goto out; }
    if (ckd_priv(ctx, &ch, index, &leaf) != 0)   { rc = -2; goto out; }
    if (pub33_of(ctx, leaf.key, pub33) != 0)     { rc = -2; goto out; }
    memcpy(leaf_key, leaf.key, 32);
    rc = 0;
out:
    wipe(&acct, sizeof(acct)); wipe(&ch, sizeof(ch)); wipe(&leaf, sizeof(leaf));
    if (rc) { wipe(pub33, 33); wipe(leaf_key, 32); }
    return rc;
}

int btc_msg_release(const secp256k1_context *ctx, const uint8_t digest32[32],
                    const uint8_t pub33[33], const secp256k1_ecdsa_recoverable_signature *rs,
                    uint8_t sig65[65]) {
    int recid = -1, rc = -3;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig65 + 1, &recid, rs) || recid < 0 || recid > 3) goto out;
    sig65[0] = (uint8_t)(27 + 12 + recid);   /* BIP-137: 39..42 = P2WPKH (bech32) */
    /* Self-check before release: recovering from what we hand out must give
     * this key, or nothing leaves the chip. */
    { secp256k1_pubkey rec; uint8_t chk[33]; size_t l = 33;
      if (!secp256k1_ecdsa_recover(ctx, &rec, rs, digest32) ||
          !secp256k1_ec_pubkey_serialize(ctx, chk, &l, &rec, SECP256K1_EC_COMPRESSED) ||
          l != 33 || memcmp(chk, pub33, 33) != 0) { rc = -4; goto out; } }
    rc = 0;
out:
    if (rc) wipe(sig65, 65);
    return rc;
}

#ifdef BTC_HOST_REFERENCE
/* Host tests only (tests/run_btc_test.py vs embit): the untweaked RFC 6979
 * signature, composed from prepare + release. NOT compiled into firmware:
 * the chip has no path to an uncommitted nonce (27 Oct 2026). */
int btc_sign_request(const secp256k1_context *ctx, const uint8_t seed[64],
                     const uint8_t req[BTC_REQ_LEN],
                     uint8_t pub33[33], uint8_t der[BTC_DER_MAX], uint8_t *der_len,
                     uint8_t sighash32[32]) {
    uint8_t leaf[32]; secp256k1_ecdsa_signature sig; int rc;
    rc = btc_sign_prepare(ctx, seed, req, leaf, pub33, sighash32);
    if (rc == 0 && !secp256k1_ecdsa_sign(ctx, &sig, sighash32, leaf, NULL, NULL)) rc = -3;
    if (rc == 0) rc = btc_sign_release(ctx, leaf, sighash32, pub33, &sig, der, der_len);
    wipe(leaf, 32); wipe(&sig, sizeof(sig));
    if (rc) { wipe(pub33, 33); wipe(der, BTC_DER_MAX); *der_len = 0; wipe(sighash32, 32); }
    return rc;
}
int btc_sign_message(const secp256k1_context *ctx, const uint8_t seed[64],
                     const uint8_t req[BTC_REQ_LEN],
                     uint8_t pub33[33], uint8_t sig65[65], uint8_t digest32[32]) {
    uint8_t leaf[32]; secp256k1_ecdsa_recoverable_signature rs; int rc;
    rc = btc_msg_prepare(ctx, seed, req, leaf, pub33, digest32);
    if (rc == 0 && !secp256k1_ecdsa_sign_recoverable(ctx, &rs, digest32, leaf, NULL, NULL)) rc = -3;
    if (rc == 0) rc = btc_msg_release(ctx, digest32, pub33, &rs, sig65);
    wipe(leaf, 32); wipe(&rs, sizeof(rs));
    if (rc) { wipe(pub33, 33); wipe(sig65, 65); }
    return rc;
}
#endif

void btc_state_key(const uint8_t seed[64], uint8_t out[32]) {
    static const uint8_t label[] = "FAVILLA-BTC-STATE-v1";
    hmac_sha256(seed, 64, label, sizeof(label) - 1, out);
}
