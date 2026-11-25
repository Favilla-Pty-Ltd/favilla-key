#pragma once
// ============================================================================
// btc_state.h — the KEY's persistent Bitcoin state, SEALED.
//
// Everything Bitcoin that must survive a power cycle lives in ONE structure:
//   - registered multisig wallets (ms_store_t: quorums, cosigner xpubs, bookmarks)
//   - the on-device address book
//   - the single-sig receive bookmark
//
// At rest it is a single AES-256-GCM blob in nvs_sec under a key derived from
// the BIP-39 seed:  K = HMAC-SHA256(seed, "FAVILLA-BTC-STATE-v1").
// The seed only ever exists in RAM inside a BTC life (true power cycle ->
// BITCOIN door -> spend PIN), so:
//   confidentiality  a flash dump / Nostr-life RCE sees opaque bytes, not xpubs
//   integrity        a Nostr-life RCE can overwrite the blob but cannot forge
//                    a valid tag; the next BTC life REFUSES it and starts empty
//   authorship       only a BTC life under the spend PIN can write state that a
//                    BTC life will believe (Josh's ruling, 14 Sep 2026)
//
// Blob layout:  "FBS1" | nonce[12] | ciphertext[n] | tag[16]
//   AAD = magic || u32 plaintext length. Fresh random nonce on every seal.
//   Plaintext is the COMPACT serialisation below (only used address-book
//   entries and only valid wallet slots), so a typical blob is ~1-2 KB and the
//   maximum (32 addresses, 4 wallets) is ~7.5 KB. nvs_sec is 64 KB.
//
// This header is pure: no NVS, no display, no SE. bitcoin_menu.inc owns the
// load/save/migrate wiring. Verified on the host by harness/multisig.
// ============================================================================

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include "multisig.h"

#define BST_VERSION       1
#define BST_MAGIC         "FBS1"
#define BST_NONCE_LEN     12
#define BST_TAG_LEN       16
#define BST_ADDR_MAX      32
#define BST_LABEL_MAX     24
#define BST_ADDRSTR_MAX   100
#define BST_KEY_LABEL     "FAVILLA-BTC-STATE-v1"

typedef struct {
  char     label[BST_LABEL_MAX];
  char     addr[BST_ADDRSTR_MAX];
  uint32_t n_sent;
} bst_addr_t;

// In-RAM plaintext (~7.6 KB). Lives in PSRAM for the BTC life only.
typedef struct {
  uint32_t   version;
  uint32_t   recv_index;          // single-sig receive bookmark
  uint32_t   addr_count;
  bst_addr_t addrs[BST_ADDR_MAX];
  ms_store_t ms;                  // registered multisig wallets
} bst_state_t;

// Serialised plaintext bound (what BST_SEALED_MAX is derived from).
#define BST_PLAIN_MAX  (4 + 4 + 4 + BST_ADDR_MAX * (int)sizeof(bst_addr_t) + 1 + MS_MAX_WALLETS * (int)sizeof(ms_wallet_t))
#define BST_SEALED_MAX (4 + BST_NONCE_LEN + BST_PLAIN_MAX + BST_TAG_LEN)

typedef void (*bst_rng_fn)(uint8_t *out, size_t len);

static void bst_init(bst_state_t *s) {
  memset(s, 0, sizeof(*s));
  s->version = BST_VERSION;
  ms_store_init(&s->ms);
}

// K = HMAC-SHA256(key = seed, msg = label). Caller zeroises the seed.
static bool bst_derive_key(const uint8_t seed[64], uint8_t key_out[32]) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return false;
  return mbedtls_md_hmac(md, seed, 64, (const uint8_t *)BST_KEY_LABEL, strlen(BST_KEY_LABEL), key_out) == 0;
}

// ── Compact serialisation ──────────────────────────────────────────────────
static void bst_w32(uint8_t *o, uint32_t v) { o[0] = v & 0xFF; o[1] = (v >> 8) & 0xFF; o[2] = (v >> 16) & 0xFF; o[3] = (v >> 24) & 0xFF; }
static uint32_t bst_r32(const uint8_t *i) { return (uint32_t)i[0] | ((uint32_t)i[1] << 8) | ((uint32_t)i[2] << 16) | ((uint32_t)i[3] << 24); }

static size_t bst_serialise(const bst_state_t *s, uint8_t *out, size_t cap) {
  if (s->addr_count > BST_ADDR_MAX) return 0;
  uint8_t nw = 0;
  for (int i = 0; i < MS_MAX_WALLETS; i++) if (s->ms.w[i].valid) nw++;
  size_t need = 12 + (size_t)s->addr_count * sizeof(bst_addr_t) + 1 + (size_t)nw * sizeof(ms_wallet_t);
  if (need > cap) return 0;
  size_t p = 0;
  bst_w32(out + p, BST_VERSION); p += 4;
  bst_w32(out + p, s->recv_index); p += 4;
  bst_w32(out + p, s->addr_count); p += 4;
  for (uint32_t i = 0; i < s->addr_count; i++) { memcpy(out + p, &s->addrs[i], sizeof(bst_addr_t)); p += sizeof(bst_addr_t); }
  out[p++] = nw;
  for (int i = 0; i < MS_MAX_WALLETS; i++) {
    if (!s->ms.w[i].valid) continue;
    memcpy(out + p, &s->ms.w[i], sizeof(ms_wallet_t)); p += sizeof(ms_wallet_t);
  }
  return p;
}

static bool bst_deserialise(const uint8_t *in, size_t len, bst_state_t *s) {
  bst_init(s);
  if (len < 13) return false;
  size_t p = 0;
  uint32_t ver = bst_r32(in + p); p += 4;
  if (ver != BST_VERSION) return false;
  s->recv_index = bst_r32(in + p); p += 4;
  uint32_t ac = bst_r32(in + p); p += 4;
  if (ac > BST_ADDR_MAX) return false;
  if (len < p + ac * sizeof(bst_addr_t) + 1) return false;
  for (uint32_t i = 0; i < ac; i++) {
    memcpy(&s->addrs[i], in + p, sizeof(bst_addr_t)); p += sizeof(bst_addr_t);
    s->addrs[i].label[BST_LABEL_MAX - 1] = 0; s->addrs[i].addr[BST_ADDRSTR_MAX - 1] = 0;   // belt and braces
  }
  s->addr_count = ac;
  uint8_t nw = in[p++];
  if (nw > MS_MAX_WALLETS) return false;
  if (len != p + (size_t)nw * sizeof(ms_wallet_t)) return false;      // exact length, no trailing bytes
  for (uint8_t i = 0; i < nw; i++) {
    memcpy(&s->ms.w[i], in + p, sizeof(ms_wallet_t)); p += sizeof(ms_wallet_t);
    s->ms.w[i].name[MS_NAME_LEN - 1] = 0;
    if (!s->ms.w[i].valid || s->ms.w[i].m < 1 || s->ms.w[i].n < s->ms.w[i].m || s->ms.w[i].n > MS_MAX_COSIGNERS) return false;
    s->ms.w[i].our_index = 0xFF;   // never trusted from storage; re-resolved from the seed-derived xpub
  }
  s->ms.count = nw;
  s->ms.version = MS_STORE_VERSION;
  return true;
}

// ── Seal / open ────────────────────────────────────────────────────────────
// Returns sealed length or 0. `scratch` must hold BST_PLAIN_MAX bytes and is
// zeroised on exit (it held the plaintext).
static size_t bst_seal(const uint8_t key[32], const bst_state_t *s, bst_rng_fn rng,
                       uint8_t *scratch, uint8_t *out, size_t out_cap) {
  size_t pl = bst_serialise(s, scratch, BST_PLAIN_MAX);
  if (!pl || out_cap < 4 + BST_NONCE_LEN + pl + BST_TAG_LEN) { memset(scratch, 0, BST_PLAIN_MAX); return 0; }
  memcpy(out, BST_MAGIC, 4);
  uint8_t *nonce = out + 4;
  rng(nonce, BST_NONCE_LEN);
  uint8_t aad[8]; memcpy(aad, BST_MAGIC, 4); bst_w32(aad + 4, (uint32_t)pl);
  mbedtls_gcm_context g; mbedtls_gcm_init(&g);
  bool ok = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
            mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, pl, nonce, BST_NONCE_LEN, aad, sizeof(aad),
                                      scratch, out + 4 + BST_NONCE_LEN, BST_TAG_LEN,
                                      out + 4 + BST_NONCE_LEN + pl) == 0;
  mbedtls_gcm_free(&g);
  memset(scratch, 0, BST_PLAIN_MAX);
  return ok ? 4 + BST_NONCE_LEN + pl + BST_TAG_LEN : 0;
}

// True and *s filled iff the blob authenticates under `key` and parses.
// Any failure leaves *s EMPTY (bst_init) — never partially filled.
static bool bst_open(const uint8_t key[32], const uint8_t *blob, size_t len,
                     uint8_t *scratch, bst_state_t *s) {
  bst_init(s);
  if (len < 4 + BST_NONCE_LEN + BST_TAG_LEN + 13 || memcmp(blob, BST_MAGIC, 4) != 0) return false;
  size_t pl = len - 4 - BST_NONCE_LEN - BST_TAG_LEN;
  if (pl > BST_PLAIN_MAX) return false;
  uint8_t aad[8]; memcpy(aad, BST_MAGIC, 4); bst_w32(aad + 4, (uint32_t)pl);
  mbedtls_gcm_context g; mbedtls_gcm_init(&g);
  bool ok = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
            mbedtls_gcm_auth_decrypt(&g, pl, blob + 4, BST_NONCE_LEN, aad, sizeof(aad),
                                     blob + 4 + BST_NONCE_LEN + pl, BST_TAG_LEN,
                                     blob + 4 + BST_NONCE_LEN, scratch) == 0;
  mbedtls_gcm_free(&g);
  if (ok) ok = bst_deserialise(scratch, pl, s);
  if (!ok) bst_init(s);
  memset(scratch, 0, BST_PLAIN_MAX);
  return ok;
}
