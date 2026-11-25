/* RFC 6979 section 3.2 for P-256 / SHA-256, feeding p256-m's random hook.
 * qlen = hlen = 256, so bits2int(T) is T and one HMAC block gives a
 * candidate. p256-m rejects a candidate that is 0 or >= n and asks again; the
 * next call then does step h.3 (K = HMAC_K(V || 0x00), V = HMAC_K(V)) before
 * the next candidate, exactly as the RFC says. */
#include "p256_det.h"
#include "p256-m.h"
#include "sha256.h"
#include <string.h>

static void wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }

static struct { uint8_t K[32], V[32]; int armed, calls; } g_d;

static const uint8_t N[32] = { 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                               0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51 };

static void hk(const uint8_t *a, size_t al, uint8_t sep, const uint8_t *b, size_t bl, const uint8_t *c, size_t cl, uint8_t out[32]) {
    uint8_t m[32 + 1 + 32 + 64]; size_t n = 0;   /* V || sep || x || h1 [|| k'], at most 129 bytes (v18) */
    memcpy(m, a, al); n = al;
    if (sep != 0xFF) m[n++] = sep;
    if (b) { memcpy(m + n, b, bl); n += bl; }
    if (c) { memcpy(m + n, c, cl); n += cl; }
    hmac_sha256(g_d.K, 32, m, n, out);
    wipe(m, sizeof m);
}

/* Called by p256-m for the nonce only (it uses no other randomness in sign). */
int p256_generate_random(uint8_t *out, unsigned len) {
    if (!g_d.armed || len != 32) return -1;
    if (g_d.calls++ > 0) {   /* the previous candidate was rejected: step h.3 */
        uint8_t k[32];
        hk(g_d.V, 32, 0x00, NULL, 0, NULL, 0, k); memcpy(g_d.K, k, 32);
        hk(g_d.V, 32, 0xFF, NULL, 0, NULL, 0, k); memcpy(g_d.V, k, 32);
        wipe(k, 32);
    }
    uint8_t v[32]; hk(g_d.V, 32, 0xFF, NULL, 0, NULL, 0, v); memcpy(g_d.V, v, 32); wipe(v, 32);
    memcpy(out, g_d.V, 32);
    return 0;
}

int p256_det_sign_raw_x(const uint8_t priv[32], const uint8_t hash[32], const uint8_t extra[32], uint8_t sig[64]) {
    /* h1 = bits2octets(hash) = hash mod n (the hash is public: a branch is fine) */
    uint8_t h1[32]; memcpy(h1, hash, 32);
    int ge = 1; for (int i = 0; i < 32; i++) { if (h1[i] != N[i]) { ge = h1[i] > N[i]; break; } }
    if (ge) { int br = 0; for (int i = 31; i >= 0; i--) { int d = (int)h1[i] - N[i] - br; br = d < 0; h1[i] = (uint8_t)d; } }
    uint8_t t[32], hx[64];   /* bits2octets(h1) || k' (RFC 6979 3.6) */
    memcpy(hx, h1, 32); if (extra) memcpy(hx + 32, extra, 32);
    const size_t hxl = extra ? 64 : 32;
    memset(g_d.V, 0x01, 32); memset(g_d.K, 0x00, 32);
    hk(g_d.V, 32, 0x00, priv, 32, hx, hxl, t); memcpy(g_d.K, t, 32);   /* d */
    hk(g_d.V, 32, 0xFF, NULL, 0, NULL, 0, t); memcpy(g_d.V, t, 32);   /* e */
    hk(g_d.V, 32, 0x01, priv, 32, hx, hxl, t); memcpy(g_d.K, t, 32);   /* f */
    hk(g_d.V, 32, 0xFF, NULL, 0, NULL, 0, t); memcpy(g_d.V, t, 32);   /* g */
    g_d.armed = 1; g_d.calls = 0;
    int rc = p256_ecdsa_sign(sig, priv, hash, 32);
    wipe(&g_d, sizeof g_d); wipe(t, 32); wipe(h1, 32); wipe(hx, sizeof hx);
    return rc == P256_SUCCESS ? 0 : -1;
}

int p256_det_sign_raw(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[64]) { return p256_det_sign_raw_x(priv, hash, NULL, sig); }

static size_t der_int(uint8_t *o, const uint8_t v[32]) {
    int i = 0; while (i < 31 && v[i] == 0) i++;
    size_t n = 32 - i; int pad = (v[i] & 0x80) != 0;
    o[0] = 0x02; o[1] = (uint8_t)(n + pad); if (pad) o[2] = 0;
    memcpy(o + 2 + pad, v + i, n);
    return 2 + pad + n;
}

size_t p256_det_sign_der_x(const uint8_t priv[32], const uint8_t hash[32], const uint8_t extra[32], uint8_t *sig_der, size_t cap) {
    uint8_t rs[64];
    if (cap < 72 || p256_det_sign_raw_x(priv, hash, extra, rs) != 0) { wipe(rs, 64); return 0; }
    uint8_t b[72]; size_t n = 2;
    n += der_int(b + n, rs); n += der_int(b + n, rs + 32);
    b[0] = 0x30; b[1] = (uint8_t)(n - 2);
    memcpy(sig_der, b, n);
    wipe(rs, 64); wipe(b, sizeof b);
    return n;
}

size_t p256_det_sign_der(const uint8_t priv[32], const uint8_t hash[32], uint8_t *sig_der, size_t cap) { return p256_det_sign_der_x(priv, hash, NULL, sig_der, cap); }
