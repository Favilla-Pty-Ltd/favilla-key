#pragma once
// =============================================================================
// mbed_secret.h - keep mbedTLS working memory for secret material on-chip
// (2 Nov 2026, review of the TLS-in-PSRAM change).
//
// main.cpp's tlsAllocInit() routes mbedTLS allocations to PSRAM so TLS does not
// break up internal RAM. That also caught HMAC contexts keyed with the seed or
// S_pk (one-block keys: ipad/opad are the key XOR a constant) and bignum limbs
// holding BIP-32 private keys. mbedTLS wipes them on free, but PSRAM is
// off-chip. Inside an MbedSecretScope every mbedTLS allocation goes to internal
// RAM instead. Nesting is counted. Other tasks allocating during a scope (WiFi)
// just get internal RAM for that moment, which is harmless.
// =============================================================================
inline volatile int g_mbedSecretDepth = 0;
struct MbedSecretScope {
  MbedSecretScope()  { g_mbedSecretDepth = g_mbedSecretDepth + 1; }
  ~MbedSecretScope() { g_mbedSecretDepth = g_mbedSecretDepth - 1; }
  MbedSecretScope(const MbedSecretScope&) = delete;
  MbedSecretScope& operator=(const MbedSecretScope&) = delete;
};
