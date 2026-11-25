#pragma once
#include <stdint.h>
#include <stddef.h>
/* TOTP for the next G0 version (Josh's ruling B, 6 Nov 2026): the shared
 * secret is unsealed and used only inside the G0; only the digits leave it.
 * RFC 4226 HOTP with HMAC-SHA1 (RFC 6238 TOTP is HOTP of floor(time/period)).
 * digits 6..8. Returns the code, or -1 for bad arguments. */
long g0_hotp_sha1(const uint8_t *key, size_t keylen, uint64_t counter, int digits);
void g0_hmac_sha1(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t n, uint8_t out[20]);
