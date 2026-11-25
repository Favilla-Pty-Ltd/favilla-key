#pragma once
#include <openssl/sha.h>
typedef SHA256_CTX mbedtls_sha256_context;
inline void mbedtls_sha256_init(mbedtls_sha256_context*){} inline int mbedtls_sha256_starts(mbedtls_sha256_context*c,int){return SHA256_Init(c)!=1;}
inline int mbedtls_sha256_update(mbedtls_sha256_context*c,const unsigned char*d,size_t n){return SHA256_Update(c,d,n)!=1;}
inline int mbedtls_sha256_finish(mbedtls_sha256_context*c,unsigned char*o){return SHA256_Final(o,c)!=1;} inline void mbedtls_sha256_free(mbedtls_sha256_context*){}
inline int mbedtls_sha256(const unsigned char*d,size_t n,unsigned char*o,int){ SHA256(d,n,o); return 0; }
