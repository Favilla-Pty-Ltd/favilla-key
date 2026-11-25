#pragma once
// =============================================================================
// vault_backup.h - relay backup of the passkey records (2 Nov 2026, Favilla
// Vault spec phase 3, section 4).
//
// One replaceable event per vault, kind 30078 (NIP-78), d-tag "favilla-vault",
// signed by the vault publishing key k_pub (derived from the words; the G0 holds
// it, see g0_vault_sign). Content = base64 of the blob:
//   "FVB1" | ver 1 | flags (bit 0: vault passphrase on; never set yet) |
//   check8 = HMAC(K_vault, "CHK")[0:8] | body (pk_records rk_export)
// The body is the sealed records exactly as stored plus tombstones: nothing is
// opened to build it, publish it, fetch it or merge it.
// This file is pure logic (no radio, no G0): the relay I/O lives in main.cpp.
// =============================================================================
#include <stdint.h>
#include <stddef.h>

// Curve helpers, defined in g0_signer.cpp (which has the ESP32's secp256k1
// code): x-only public key of a secret key (false when k is 0 or >= n), and
// BIP-340 verification.
bool vbh_xonly_pub(const uint8_t k[32], uint8_t x32[32]);
bool vbh_schnorr_verify(const uint8_t pub32[32], const uint8_t msg32[32], const uint8_t sig64[64]);

namespace favilla {

constexpr const char* VB_D_TAG    = "favilla-vault";
constexpr const char* VB_ALT      = "Favilla KEY vault backup";
constexpr const char* VB_RELAY    = "vault.favillakey.io";   // default vault relay (its own name; never in the Nostr list)
constexpr uint8_t     VB_VER      = 1;
constexpr size_t      VB_HDR      = 4 + 1 + 1 + 8;           // magic, ver, flags, check
constexpr size_t      VB_EVENT_MAX = 160 * 1024 - 2048;      // 11dr: the KEY reads a relay frame of up to 160 KB (WEBSOCKETS_MAX_DATA_SIZE), so no
                                                             // event bigger than it can hold is published: a backup it could not restore is no backup
constexpr size_t      VB_BLOB_MAX = 128 * 1024;              // P4-1 (3 Nov 2026): 200 records x 513 B + 128 tombstones + header is about 102 KB (PSRAM; was 32 KB for 50)

enum VbErr {
  VB_OK = 0,
  VB_E_FORMAT   = -20,   // not a Favilla vault blob, or a field out of range
  VB_E_VERSION  = -21,   // a newer blob version than this firmware reads
  VB_E_PASS     = -22,   // the backup is marked "vault passphrase on" (not supported yet)
  VB_E_CHECK    = -23,   // check value differs: another vault (other words)
  VB_E_EVENT    = -24,   // the event is not ours: author, kind, tags, id or signature
  VB_E_SIZE     = -25,
};

// The publishing key's x-only public key and the check value, from S_pk (the
// passkey master). Onboarding computes these while it holds S_pk, so a
// restore from the words can find the backup before any PASSKEY login.
// Same derivation as the G0 (vpub_glue.inc): K_vault = HMAC(S_pk,
// "FAVILLA-VAULT-v1"); k = first HMAC(K_vault, "PUB" || ctr) that is a valid
// secp256k1 key; P = x(k*G); check = HMAC(K_vault, "CHK")[0:8]. k is wiped.
bool vb_derive(const uint8_t spk[32], uint8_t pub32[32], uint8_t chk8[8]);

// Blob from a body (header + body). out must hold VB_HDR + bodyN.
size_t vb_blob(const uint8_t chk8[8], const uint8_t* body, size_t bodyN, uint8_t* out);
// Parse a blob: checks magic, version, flags and the check value; points at the body.
int vb_blob_parse(const uint8_t* blob, size_t n, const uint8_t chk8[8], const uint8_t** body, size_t* bodyN);

// The event id (NIP-01) for our fixed tag set. content is the base64 text.
void vb_event_id(const char pubHex[65], uint32_t createdAt, const char* content, size_t contentN, uint8_t id32[32]);
// Full event JSON into out (cap bytes). Returns length or 0.
size_t vb_event_json(char* out, size_t cap, const uint8_t id32[32], const char pubHex[65], uint32_t createdAt,
                     const char* content, size_t contentN, const uint8_t sig64[64]);
// Check an event a relay returned (the JSON object, not the ["EVENT",...] frame):
// author == pub32, kind 30078, tags exactly [d favilla-vault] (+ an optional
// plain alt), the id recomputed, the BIP-340 signature. On success *contentAt
// and *contentN point into json (base64 text) and *createdAt is set.
int vb_event_check(const char* json, size_t n, const uint8_t pub32[32], const char** contentAt, size_t* contentN, uint32_t* createdAt);

}  // namespace favilla
