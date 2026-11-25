#pragma once
#include <stdint.h>
#include <stddef.h>
typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t blen; } sha256_ctx;
void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *d, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const uint8_t *d, size_t n, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32]);
void hkdf_sha256_32(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen,
                    const uint8_t *info, size_t nlen, uint8_t out[32]);
