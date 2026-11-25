/* ember_tx.c — see ember_tx.h. 28 Oct 2026. */
#include "ember_tx.h"
#include "sha256.h"
#include "ripemd160.h"
#include <string.h>

typedef struct { sha256_ctx *h; uint8_t *buf; size_t n, cap; } sink_t;
static void put(sink_t *s, const uint8_t *d, size_t n) {
    if (s->h) sha256_update(s->h, d, n);
    if (s->buf && s->n + n <= s->cap) memcpy(s->buf + s->n, d, n);
    s->n += n;
}
static void put8(sink_t *s, uint8_t v) { put(s, &v, 1); }
static void put32(sink_t *s, uint32_t v) { uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) }; put(s, b, 4); }
static void put64(sink_t *s, uint64_t v) { put32(s, (uint32_t)v); put32(s, (uint32_t)(v >> 32)); }

uint8_t et_spk_len(const uint8_t s[34]) {
    uint8_t len = 0;
    if (s[0] == 0x00 && s[1] == 0x14) len = 22;                                    /* P2WPKH */
    else if ((s[0] == 0x00 || s[0] == 0x51) && s[1] == 0x20) len = 34;              /* P2WSH, P2TR */
    else if (s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac) len = 25; /* P2PKH */
    else if (s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) len = 23;               /* P2SH */
    else return 0;
    for (int i = len; i < 34; i++) if (s[i]) return 0;                              /* padding must be zero */
    return len;
}

void et_p2wpkh_spk(const uint8_t pub[33], uint8_t spk[22]) {
    spk[0] = 0x00; spk[1] = 0x14; hash160(pub, 33, spk + 2);
}

static void body(sink_t *s, const et_tx_t *tx, int wit) {
    put32(s, tx->version);
    if (wit) { put8(s, 0x00); put8(s, 0x01); }
    put8(s, tx->nin);
    for (int i = 0; i < tx->nin; i++) {
        put(s, tx->in[i].txid, 32); put32(s, tx->in[i].vout);
        put8(s, 0x00);                                     /* empty scriptSig (native segwit) */
        put32(s, tx->in[i].seq);
    }
    put8(s, tx->nout);
    for (int i = 0; i < tx->nout; i++) {
        put64(s, tx->out[i].amount); put8(s, tx->out[i].spklen); put(s, tx->out[i].spk, tx->out[i].spklen);
    }
    if (wit) for (int i = 0; i < tx->nin; i++) {
        put8(s, 0x02);
        put8(s, tx->in[i].siglen); put(s, tx->in[i].sig, tx->in[i].siglen);
        put8(s, 33); put(s, tx->in[i].pub, 33);
    }
    put32(s, tx->locktime);
}

size_t et_serialize(const et_tx_t *tx, int with_witness, uint8_t *buf, size_t cap) {
    sink_t s = { 0, buf, 0, cap }; body(&s, tx, with_witness); return s.n;
}

void et_txid(const et_tx_t *tx, uint8_t out[32]) {
    sha256_ctx h; sink_t s = { &h, 0, 0, 0 }; uint8_t t[32];
    sha256_init(&h); body(&s, tx, 0); sha256_final(&h, t); sha256(t, 32, out);
}

void et_sighash(const et_tx_t *tx, int i, uint8_t out[32]) {
    sha256_ctx h; sink_t s = { &h, 0, 0, 0 }; uint8_t prev[32], seq[32], outs[32], t[32];
    sha256_init(&h); for (int k = 0; k < tx->nin; k++) { put(&s, tx->in[k].txid, 32); put32(&s, tx->in[k].vout); }
    sha256_final(&h, t); sha256(t, 32, prev);
    sha256_init(&h); for (int k = 0; k < tx->nin; k++) put32(&s, tx->in[k].seq);
    sha256_final(&h, t); sha256(t, 32, seq);
    sha256_init(&h); for (int k = 0; k < tx->nout; k++) { put64(&s, tx->out[k].amount); put8(&s, tx->out[k].spklen); put(&s, tx->out[k].spk, tx->out[k].spklen); }
    sha256_final(&h, t); sha256(t, 32, outs);
    const et_in_t *in = &tx->in[i];
    uint8_t sc[26] = { 0x19, 0x76, 0xa9, 0x14 }; hash160(in->pub, 33, sc + 4); sc[24] = 0x88; sc[25] = 0xac;
    sha256_init(&h);
    put32(&s, tx->version); put(&s, prev, 32); put(&s, seq, 32);
    put(&s, in->txid, 32); put32(&s, in->vout);
    put(&s, sc, 26); put64(&s, in->amount); put32(&s, in->seq);
    put(&s, outs, 32); put32(&s, tx->locktime); put32(&s, 1);   /* SIGHASH_ALL */
    sha256_final(&h, t); sha256(t, 32, out);
}

uint32_t et_vsize_max(const et_tx_t *tx) {
    uint32_t base = (uint32_t)et_serialize(tx, 0, 0, 0);
    uint32_t wit = 2 + tx->nin * (1 + 1 + 73 + 1 + 33);       /* marker+flag, per input: count, sig(72+1), key */
    return (base * 4 + wit + 3) / 4;
}

int64_t et_fee(const et_tx_t *tx) {
    uint64_t a = 0, b = 0;
    for (int i = 0; i < tx->nin; i++) a += tx->in[i].amount;
    for (int i = 0; i < tx->nout; i++) b += tx->out[i].amount;
    return b > a ? -1 : (int64_t)(a - b);
}
