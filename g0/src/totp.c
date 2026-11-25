/* SHA-1, HMAC-SHA1 and HOTP for the G0 (v17, VAULT op TOTP; not yet in an
 * audited build). Small and plain: SHA-1 is only used here as the HMAC inside TOTP,
 * where its collision weakness does not matter (RFC 6238 still specifies it,
 * and nearly every site issues SHA-1 TOTP secrets). Every buffer that held
 * key material is wiped through volatile before return. */
#include "totp.h"
#include <string.h>

static void wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }
static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

typedef struct { uint32_t h[5]; uint8_t buf[64]; uint64_t len; size_t used; } sha1_t;
static void sha1_block(sha1_t *s, const uint8_t *p) {
    uint32_t w[16], a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 0; i < 80; i++) {
        if (i >= 16) w[i & 15] = rol(w[(i+13)&15] ^ w[(i+8)&15] ^ w[(i+2)&15] ^ w[i&15], 1);
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i & 15];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
    wipe(w, sizeof w);
}
static void sha1_init(sha1_t *s) { static const uint32_t iv[5] = {0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0}; memcpy(s->h, iv, 20); s->len = 0; s->used = 0; }
static void sha1_add(sha1_t *s, const uint8_t *p, size_t n) {
    s->len += n;
    while (n) { size_t k = 64 - s->used; if (k > n) k = n; memcpy(s->buf + s->used, p, k); s->used += k; p += k; n -= k;
        if (s->used == 64) { sha1_block(s, s->buf); s->used = 0; } }
}
static void sha1_end(sha1_t *s, uint8_t out[20]) {
    uint64_t bits = s->len * 8; uint8_t pad = 0x80, z = 0, l[8];
    sha1_add(s, &pad, 1); while (s->used != 56) sha1_add(s, &z, 1);
    for (int i = 0; i < 8; i++) l[i] = (uint8_t)(bits >> (56 - 8*i));
    sha1_add(s, l, 8);
    for (int i = 0; i < 5; i++) { out[4*i] = (uint8_t)(s->h[i] >> 24); out[4*i+1] = (uint8_t)(s->h[i] >> 16); out[4*i+2] = (uint8_t)(s->h[i] >> 8); out[4*i+3] = (uint8_t)s->h[i]; }
    wipe(s, sizeof *s);
}
void g0_hmac_sha1(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t n, uint8_t out[20]) {
    uint8_t k[64] = {0}, pad[64], ih[20]; sha1_t s;
    if (keylen > 64) { sha1_init(&s); sha1_add(&s, key, keylen); sha1_end(&s, k); } else memcpy(k, key, keylen);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha1_init(&s); sha1_add(&s, pad, 64); sha1_add(&s, msg, n); sha1_end(&s, ih);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha1_init(&s); sha1_add(&s, pad, 64); sha1_add(&s, ih, 20); sha1_end(&s, out);
    wipe(k, sizeof k); wipe(pad, sizeof pad); wipe(ih, sizeof ih);
}
long g0_hotp_sha1(const uint8_t *key, size_t keylen, uint64_t counter, int digits) {
    if (!key || keylen == 0 || keylen > 64 || digits < 6 || digits > 8) return -1;
    uint8_t c[8], h[20];
    for (int i = 0; i < 8; i++) c[i] = (uint8_t)(counter >> (56 - 8*i));
    g0_hmac_sha1(key, keylen, c, 8, h);
    const int o = h[19] & 0x0F;
    uint32_t bin = ((uint32_t)(h[o] & 0x7F) << 24) | ((uint32_t)h[o+1] << 16) | ((uint32_t)h[o+2] << 8) | h[o+3];
    static const uint32_t MOD[3] = { 1000000u, 10000000u, 100000000u };
    long code = (long)(bin % MOD[digits - 6]);
    wipe(h, sizeof h); bin = 0;
    return code;
}
