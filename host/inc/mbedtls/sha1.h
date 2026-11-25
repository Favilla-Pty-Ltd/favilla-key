#pragma once
// host stub over OpenSSL: the one-shot SHA-1 the record store uses for password health (11s)
#include <openssl/sha.h>
#include <stddef.h>
inline int mbedtls_sha1(const unsigned char* in, size_t n, unsigned char out[20]) { return SHA1(in, n, out) ? 0 : -1; }
