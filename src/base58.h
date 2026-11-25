#ifndef FAVILLA_BASE58_H
#define FAVILLA_BASE58_H

// Base58Check encoding for serialised BIP-32 extended keys (xpub/zpub).
// Encode-only; the device never imports an xpub.

#include <stdint.h>
#include <string.h>
#include "mbedtls/sha256.h"

static const char B58_ALPHABET[] =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void b58_dsha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  uint8_t first[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, first);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, first, 32);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

// Encode bytes as base58. Returns chars written (excl. null), 0 on failure.
static size_t base58_encode(const uint8_t* in, size_t in_len,
                             char* out, size_t out_cap) {
  if (in_len == 0) return 0;

  size_t leading_zeros = 0;
  while (leading_zeros < in_len && in[leading_zeros] == 0) leading_zeros++;

  uint8_t buf[128];
  if (in_len > sizeof(buf)) return 0;
  memcpy(buf, in, in_len);

  char digits[180];
  size_t digits_n = 0;

  size_t start = leading_zeros;
  while (start < in_len) {
    int remainder = 0;
    for (size_t i = start; i < in_len; i++) {
      int acc = remainder * 256 + buf[i];
      buf[i] = acc / 58;
      remainder = acc % 58;
    }
    digits[digits_n++] = B58_ALPHABET[remainder];
    if (digits_n >= sizeof(digits)) return 0;
    while (start < in_len && buf[start] == 0) start++;
  }

  size_t total = leading_zeros + digits_n;
  if (total + 1 > out_cap) return 0;

  size_t pos = 0;
  for (size_t i = 0; i < leading_zeros; i++) out[pos++] = '1';
  for (size_t i = 0; i < digits_n; i++) out[pos++] = digits[digits_n - 1 - i];
  out[pos] = 0;
  return pos;
}

static size_t base58check_encode(const uint8_t* payload, size_t payload_len,
                                  char* out, size_t out_cap) {
  uint8_t buf[128];
  if (payload_len + 4 > sizeof(buf)) return 0;
  memcpy(buf, payload, payload_len);

  uint8_t check[32];
  b58_dsha256(payload, payload_len, check);
  memcpy(buf + payload_len, check, 4);

  return base58_encode(buf, payload_len + 4, out, out_cap);
}

#endif // FAVILLA_BASE58_H
