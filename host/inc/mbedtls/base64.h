#pragma once
// host stub over OpenSSL
#include <openssl/evp.h>
#include <stddef.h>
#include <string.h>
#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL -0x002A
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER -0x002C
inline int mbedtls_base64_encode(unsigned char* dst, size_t dlen, size_t* olen, const unsigned char* src, size_t slen) {
  size_t need = 4 * ((slen + 2) / 3); if (dlen < need + 1) { *olen = need + 1; return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL; }
  *olen = (size_t)EVP_EncodeBlock(dst, src, (int)slen); return 0;
}
inline int mbedtls_base64_decode(unsigned char* dst, size_t dlen, size_t* olen, const unsigned char* src, size_t slen) {
  if (slen % 4) return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
  for (size_t i = 0; i < slen; i++) { unsigned char c = src[i]; if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=')) return MBEDTLS_ERR_BASE64_INVALID_CHARACTER; }
  size_t pad = (slen && src[slen-1]=='=') + (slen>1 && src[slen-2]=='=');
  size_t need = slen / 4 * 3 - pad; if (dlen < need) { *olen = need; return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL; }
  int n = EVP_DecodeBlock(dst, src, (int)slen); if (n < 0) return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
  *olen = (size_t)n - pad; return 0;
}
