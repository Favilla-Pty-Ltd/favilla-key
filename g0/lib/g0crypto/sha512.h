#pragma once
#include <stdint.h>
#include <stddef.h>
typedef struct { uint64_t h[8]; uint64_t len; uint8_t buf[128]; size_t blen; } sha512_ctx;
void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const uint8_t *d, size_t n);
void sha512_final(sha512_ctx *c, uint8_t out[64]);
void sha512(const uint8_t *d, size_t n, uint8_t out[64]);
void hmac_sha512(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[64]);
