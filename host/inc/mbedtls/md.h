#pragma once
// host stub over OpenSSL: just the HMAC-SHA256 path the firmware uses
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stddef.h>
typedef int mbedtls_md_type_t;
#define MBEDTLS_MD_SHA256 6
typedef struct { int t; } mbedtls_md_info_t;
inline const mbedtls_md_info_t* mbedtls_md_info_from_type(mbedtls_md_type_t t) { static mbedtls_md_info_t i{6}; (void)t; return &i; }
inline int mbedtls_md_hmac(const mbedtls_md_info_t*, const unsigned char* k, size_t kl, const unsigned char* m, size_t ml, unsigned char* out) {
  unsigned int l = 32; return HMAC(EVP_sha256(), k, (int)kl, m, ml, out, &l) ? 0 : -1;
}
