// Host shim: stand in for the ESP32/mbedtls surface bip39.h expects, so the
// SAME source file can be compiled on the desktop under sanitizers.
// Nothing here is used on device — it exists only to make the real code
// buildable outside the firmware.
#pragma once
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "sha256.h"

#define PROGMEM

typedef struct { sctx c; } mbedtls_sha256_context;
static inline void mbedtls_sha256_init(mbedtls_sha256_context* c){ (void)c; }
static inline void mbedtls_sha256_free(mbedtls_sha256_context* c){ (void)c; }
static inline int  mbedtls_sha256_starts(mbedtls_sha256_context* c, int is224){ (void)is224; sinit(&c->c); return 0; }
static inline int  mbedtls_sha256_update(mbedtls_sha256_context* c, const unsigned char* d, size_t n){ supd(&c->c, d, n); return 0; }
static inline int  mbedtls_sha256_finish(mbedtls_sha256_context* c, unsigned char* o){ sfin(&c->c, o); return 0; }
static inline void mbedtls_platform_zeroize(void* p, size_t n){ memset(p, 0, n); }
