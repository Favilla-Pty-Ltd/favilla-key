// =============================================================================
// nostr_verify.h - check a received Nostr event (11bl, issues #41 and #45).
//
// The id is recomputed from the event's own fields (NIP-01, written exactly as
// JSON.stringify does, nostr_canon.h) and must equal "id"; "sig" must be a
// BIP-340 signature of that id by "pubkey". This is what every Nostr client
// does with what a relay sends; the KEY's bunker and its NIP-17 unwrap did not.
//
// Pure code: the caller passes the BIP-340 verifier and the allocator (PSRAM on
// the KEY), so the host test (tests/event_verify_test.cpp) runs this file as is.
// =============================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <ArduinoJson.h>
#include "mbedtls/sha256.h"
#include "nostr_canon.h"

namespace nostrverify {

typedef bool (*VerifyFn)(const uint8_t pub32[32], const uint8_t msg32[32], const uint8_t sig64[64]);
typedef void* (*AllocFn)(size_t);

inline bool unhex(const char* s, uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; i++) {
    uint8_t v = 0;
    for (int k = 0; k < 2; k++) {
      char c = s[2 * i + k]; uint8_t d;
      if (c >= '0' && c <= '9') d = (uint8_t)(c - '0');
      else if (c >= 'a' && c <= 'f') d = (uint8_t)(c - 'a' + 10);
      else return false;   // lower case only, as NIP-01 writes them
      v = (uint8_t)(v << 4 | d);
    }
    out[i] = v;
  }
  return true;
}

// srcLen: the length of the JSON the event was parsed from. The preimage is
// never longer than that plus a little (parsing only shortens escapes), so it
// sizes the buffer. false on any missing or malformed field, an id that is not
// the hash of the fields, or a signature that does not verify.
inline bool eventOk(JsonVariantConst ev, size_t srcLen, VerifyFn verify, AllocFn alloc = malloc) {
  if (!ev.is<JsonObjectConst>() || !verify || !alloc) return false;
  const char* id = ev["id"] | ""; const char* pk = ev["pubkey"] | ""; const char* sig = ev["sig"] | "";
  if (strlen(id) != 64 || strlen(pk) != 64 || strlen(sig) != 128) return false;
  if (!ev["created_at"].is<long long>() || !ev["kind"].is<long long>() || !ev["content"].is<const char*>()) return false;
  if (!ev["tags"].isNull() && !ev["tags"].is<JsonArrayConst>()) return false;
  uint8_t id32[32], pk32[32], sig64[64], calc[32];
  if (!unhex(id, id32, 32) || !unhex(pk, pk32, 32) || !unhex(sig, sig64, 64)) return false;
  const size_t cap = srcLen + 256;
  char* buf = (char*)alloc(cap);
  if (!buf) return false;
  const size_t n = nostrcanon::eventPreimage(pk, ev["created_at"], ev["kind"], ev["tags"], ev["content"] | "", buf, cap);
  if (n) {
    mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, (const uint8_t*)buf, n); mbedtls_sha256_finish(&c, calc); mbedtls_sha256_free(&c);
  }
  free(buf);
  if (!n || memcmp(calc, id32, 32) != 0) return false;
  return verify(pk32, id32, sig64);
}

}  // namespace nostrverify
