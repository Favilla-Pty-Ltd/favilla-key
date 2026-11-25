#include "pbkdf2.h"
#include "sha512.h"
#include <string.h>

static void wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }

void pbkdf2_hmac_sha512_64(const uint8_t *pw, size_t pwlen,
                           const uint8_t *salt, size_t saltlen,
                           uint32_t iters, uint8_t out[64]) {
    uint8_t k[128]; memset(k, 0, sizeof(k));
    if (pwlen > 128) { sha512(pw, pwlen, k); }          /* HMAC: long keys are hashed */
    else memcpy(k, pw, pwlen);
    uint8_t pad[128];
    sha512_ctx inner0, outer0, c;
    for (int i = 0; i < 128; i++) pad[i] = k[i] ^ 0x36;
    sha512_init(&inner0); sha512_update(&inner0, pad, 128);
    for (int i = 0; i < 128; i++) pad[i] = k[i] ^ 0x5c;
    sha512_init(&outer0); sha512_update(&outer0, pad, 128);
    wipe(pad, sizeof(pad)); wipe(k, sizeof(k));

    /* U1 = HMAC(pw, salt || INT(1)) */
    uint8_t u[64], t[64];
    static const uint8_t one[4] = {0, 0, 0, 1};
    c = inner0; sha512_update(&c, salt, saltlen); sha512_update(&c, one, 4); sha512_final(&c, u);
    c = outer0; sha512_update(&c, u, 64); sha512_final(&c, u);
    memcpy(t, u, 64);
    for (uint32_t i = 1; i < iters; i++) {
        c = inner0; sha512_update(&c, u, 64); sha512_final(&c, u);
        c = outer0; sha512_update(&c, u, 64); sha512_final(&c, u);
        for (int j = 0; j < 64; j++) t[j] ^= u[j];
    }
    memcpy(out, t, 64);
    wipe(u, 64); wipe(t, 64); wipe(&inner0, sizeof(inner0)); wipe(&outer0, sizeof(outer0)); wipe(&c, sizeof(c));
}
