#pragma once
// ============================================================================
// multisig.h — BIP-48 P2WSH sortedmulti COSIGNER support for the Favilla KEY.
//
// Scope (agreed 14 Sep 2026):
//   - The KEY is a cosigner only. It never coordinates a quorum.
//   - Script type: P2WSH sortedmulti(m, ...) at m/48'/0'/0'/2' for every
//     cosigner. No P2SH-wrapped, no taproot, no per-cosigner exotic paths.
//   - A wallet must be REGISTERED (threshold + every cosigner's fingerprint,
//     path and account xpub) before the KEY will verify or sign for it. The
//     PSBT is never allowed to propose the quorum: every cosigner pubkey used
//     for verification is re-derived (CKD-pub) from the REGISTERED xpub, never
//     read from the PSBT.
//   - Up to MS_MAX_WALLETS wallets x MS_MAX_COSIGNERS cosigners, fixed buffers,
//     no heap. The whole ms_store_t is one POD blob for NVS (Drop 3 wraps it in
//     the seed-derived HMAC alongside the address book).
//   - Mixed PSBTs (our P2WPKH inputs AND our P2WSH inputs) are REFUSED.
//   - Receive is browse + scan-to-verify: ms_search_spk() finds which
//     (change,index) a scanned address belongs to, or says it is not ours.
//
// What this header does NOT do: display anything, touch NVS, or open an SE
// session. bitcoin_menu.inc (Drop 2) owns all of that.
//
// Every function is verified on the host by harness/multisig/test_multisig.cpp
// against vectors produced independently with embit (gen_vectors.py).
// ============================================================================

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <mbedtls/sha256.h>
#include "psbt.h"
#include "psbt_sign.h"        // psbt_summary_t, psbt_partial_sig_t, PSBT_CHANGE_GAP_LIMIT
#include "bip32.h"
#include "bip143.h"
#include "secp256k1_ecdsa.h"
#include "bech32.h"
#include "base58.h"

// Diagnostic logging. This header is included from main.cpp before the LOG_*
// macros exist (same situation as psbt_sign.h's PSBTDIAG), so it carries its
// own. Arduino.h precedes it, so Serial is available.
#ifndef MS_LOG
  #define MS_LOG(...) Serial.printf(__VA_ARGS__)
#endif

#ifndef MS_MAX_COSIGNERS
#define MS_MAX_COSIGNERS 7      // must be <= PSBT_MAX_KEYS
#endif
#ifndef MS_MAX_WALLETS
#define MS_MAX_WALLETS   4
#endif
#define MS_NAME_LEN      24     // display name, NUL-terminated
#define MS_PATH_MAX      8
#define MS_STORE_VERSION 1

// The one path this build accepts for every cosigner: m/48'/0'/0'/2' (BIP-48,
// mainnet, account 0, native segwit P2WSH).
static const uint32_t MS_BIP48_PATH[4] = { 0x80000030UL, 0x80000000UL, 0x80000000UL, 0x80000002UL };
#define MS_BIP48_DEPTH 4

// BIP-32 version bytes we accept on import / emit on export.
static const uint8_t MS_VER_XPUB[4] = { 0x04, 0x88, 0xB2, 0x1E };   // xpub (Sparrow default)
static const uint8_t MS_VER_ZPUB[4] = { 0x02, 0xAA, 0x7E, 0xD3 };   // Zpub (SLIP-132 P2WSH multisig)

// ── Registered wallet model ─────────────────────────────────────────────────
typedef struct {
  uint8_t    fp[4];                    // master fingerprint of this cosigner
  uint32_t   path[MS_PATH_MAX];        // account path (always MS_BIP48_PATH in V1)
  uint8_t    path_len;
  bip32_xpub xpub;                     // account-level public key (m/48'/0'/0'/2')
} ms_cosigner_t;

typedef struct {
  uint8_t       valid;                 // 1 = slot in use
  char          name[MS_NAME_LEN];
  uint8_t       m;                     // threshold
  uint8_t       n;                     // cosigner count
  uint8_t       our_index;             // which cosigner is this device (0xFF = not yet resolved)
  ms_cosigner_t cs[MS_MAX_COSIGNERS];
  uint32_t      recv_bookmark;         // last receive index shown on-device (convenience only)
} ms_wallet_t;

typedef struct {
  uint8_t     version;                 // MS_STORE_VERSION
  uint8_t     count;                   // valid wallets (slots may be sparse; use ->valid)
  ms_wallet_t w[MS_MAX_WALLETS];
} ms_store_t;

// ── Small helpers ───────────────────────────────────────────────────────────
static void ms_sha256(const uint8_t *in, size_t len, uint8_t out[32]) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, in, len);
  mbedtls_sha256_finish(&c, out);
  mbedtls_sha256_free(&c);
}

static bool ms_path_is_bip48(const uint32_t *path, uint8_t len) {
  if (len != MS_BIP48_DEPTH) return false;
  for (int i = 0; i < MS_BIP48_DEPTH; i++) if (path[i] != MS_BIP48_PATH[i]) return false;
  return true;
}

// ── Base58Check DECODE (base58.h is encode-only) ────────────────────────────
// Returns payload length (checksum stripped and verified) or -1.
static int ms_base58check_decode(const char *s, size_t slen, uint8_t *out, size_t out_cap) {
  if (slen == 0 || slen > 128) return -1;
  uint8_t buf[128]; size_t blen = 0;          // big-endian big integer
  memset(buf, 0, sizeof(buf));
  size_t zeros = 0;
  for (size_t i = 0; i < slen && s[i] == '1'; i++) zeros++;
  for (size_t i = zeros; i < slen; i++) {
    const char *p = strchr(B58_ALPHABET, s[i]);
    if (!p || s[i] == 0) return -1;
    uint32_t carry = (uint32_t)(p - B58_ALPHABET);
    for (size_t j = 0; j < blen; j++) {
      carry += (uint32_t)buf[sizeof(buf) - 1 - j] * 58U;
      buf[sizeof(buf) - 1 - j] = (uint8_t)(carry & 0xFF);
      carry >>= 8;
    }
    while (carry) {
      if (blen >= sizeof(buf)) return -1;
      buf[sizeof(buf) - 1 - blen] = (uint8_t)(carry & 0xFF);
      blen++;
      carry >>= 8;
    }
  }
  size_t total = zeros + blen;
  if (total < 4 || total > out_cap + 4) return -1;
  uint8_t tmp[132];
  memset(tmp, 0, zeros);
  memcpy(tmp + zeros, buf + sizeof(buf) - blen, blen);
  uint8_t h[32];
  b58_dsha256(tmp, total - 4, h);
  if (memcmp(h, tmp + total - 4, 4) != 0) return -1;   // checksum
  memcpy(out, tmp, total - 4);
  return (int)(total - 4);
}

// ── xpub string <-> bip32_xpub ─────────────────────────────────────────────
// Accepts xpub or Zpub (both are the same 78-byte layout; only the version
// differs). Refuses anything that is not depth 4 (an account key) — a wallet
// config carrying a master or deeper key is not a valid BIP-48 config.
static bool ms_xpub_from_string(const char *s, size_t slen, bip32_xpub *out) {
  uint8_t ser[78];
  int n = ms_base58check_decode(s, slen, ser, sizeof(ser));
  if (n != 78) return false;
  if (memcmp(ser, MS_VER_XPUB, 4) != 0 && memcmp(ser, MS_VER_ZPUB, 4) != 0) return false;
  memset(out, 0, sizeof(*out));
  out->depth = ser[4];
  memcpy(out->parent_fingerprint, ser + 5, 4);
  out->child_number = ((uint32_t)ser[9] << 24) | ((uint32_t)ser[10] << 16) |
                      ((uint32_t)ser[11] << 8) | (uint32_t)ser[12];
  memcpy(out->chain_code, ser + 13, 32);
  memcpy(out->pubkey, ser + 45, 33);
  if (out->pubkey[0] != 0x02 && out->pubkey[0] != 0x03) return false;
  // Must be a real curve point — a garbage x would poison every derivation.
  Pt p; if (!bip32_pub_decompress(out->pubkey, &p)) return false;
  return true;
}

static bool ms_xpub_to_string(const bip32_xpub *x, const uint8_t version[4],
                              char *out, size_t out_cap) {
  if (out_cap < 128) return false;
  uint8_t ser[78];
  memcpy(ser, version, 4);
  ser[4] = x->depth;
  memcpy(ser + 5, x->parent_fingerprint, 4);
  ser[9]  = (x->child_number >> 24) & 0xFF; ser[10] = (x->child_number >> 16) & 0xFF;
  ser[11] = (x->child_number >>  8) & 0xFF; ser[12] =  x->child_number        & 0xFF;
  memcpy(ser + 13, x->chain_code, 32);
  memcpy(ser + 45, x->pubkey, 33);
  return base58check_encode(ser, 78, out, out_cap) > 0;
}

// ── Our own BIP-48 account key ─────────────────────────────────────────────
// m/48'/0'/0'/2' from the seed. Same walk as bip84_derive_account_xprv but one
// level deeper. Seed-requiring: call only inside the BTC door with the seed
// transiently unwrapped; zero the xprv after use.
static bool ms_derive_account_xprv(const uint8_t seed[64], bip32_xprv *acct_out,
                                   uint8_t master_fp_out[4]) {
  bip32_xprv cur, next;
  if (!bip32_master_from_seed(seed, 64, &cur)) return false;
  uint8_t pub[33], h160[20];
  if (!bip32_priv_to_pub_compressed(cur.key, pub)) return false;
  hash160(pub, 33, h160);
  memcpy(master_fp_out, h160, 4);
  for (int i = 0; i < MS_BIP48_DEPTH; i++) {
    if (!bip32_derive_child(&cur, MS_BIP48_PATH[i], &next)) { memset(&cur, 0, sizeof(cur)); return false; }
    if (!bip32_priv_to_pub_compressed(cur.key, pub)) { memset(&cur, 0, sizeof(cur)); memset(&next, 0, sizeof(next)); return false; }
    hash160(pub, 33, h160);
    memcpy(next.parent_fingerprint, h160, 4);
    cur = next;
  }
  memset(&next, 0, sizeof(next));
  *acct_out = cur;
  memset(&cur, 0, sizeof(cur));
  return true;
}

// Public image of our account key, for registration matching and export.
static bool ms_derive_account_xpub(const uint8_t seed[64], bip32_xpub *xpub_out,
                                   uint8_t master_fp_out[4]) {
  bip32_xprv acct;
  if (!ms_derive_account_xprv(seed, &acct, master_fp_out)) return false;
  bool ok = bip32_xprv_to_xpub(&acct, xpub_out);
  memset(&acct, 0, sizeof(acct));
  return ok;
}

// Leaf private key at m/48'/0'/0'/2'/change/index. Caller zeroises.
static bool ms_derive_leaf_privkey(const uint8_t seed[64], uint32_t change, uint32_t index,
                                   uint8_t priv_out[32]) {
  if (change > 1 || (index & 0x80000000UL)) return false;
  bip32_xprv acct, c, leaf; uint8_t fp[4];
  if (!ms_derive_account_xprv(seed, &acct, fp)) return false;
  bool ok = bip32_derive_child(&acct, change, &c) && bip32_derive_child(&c, index, &leaf);
  if (ok) memcpy(priv_out, leaf.key, 32);
  memset(&acct, 0, sizeof(acct)); memset(&c, 0, sizeof(c)); memset(&leaf, 0, sizeof(leaf));
  return ok;
}

// Key expression for Sparrow's "Add cosigner": [fp/48h/0h/0h/2h]xpub...
// ── Wallet descriptor (25 Sep 2026): the BIP-48 sortedmulti descriptor for a
// registered wallet, with the BIP-380 checksum. This is the backup that lets
// any two cosigners rebuild the wallet - two keys without it cannot derive
// the third xpub, so cannot rebuild the address. Cosigners in the stored
// order (sortedmulti makes the on-chain order key-sorted regardless). ─────
#include "descsum.h"
static bool ms_wallet_descriptor(const ms_wallet_t *w, char *out, size_t out_cap, char checksum_out[9]) {
  size_t n = (size_t)snprintf(out, out_cap, "wsh(sortedmulti(%u", (unsigned)w->m);
  for (int i = 0; i < w->n; i++) {
    char xs[128];
    if (!ms_xpub_to_string(&w->cs[i].xpub, MS_VER_XPUB, xs, sizeof(xs))) return false;
    int k = snprintf(out + n, out_cap - n, ",[%02x%02x%02x%02x/48h/0h/0h/2h]%s/<0;1>/*",
                     w->cs[i].fp[0], w->cs[i].fp[1], w->cs[i].fp[2], w->cs[i].fp[3], xs);
    if (k < 0 || (size_t)k >= out_cap - n) return false;
    n += (size_t)k;
  }
  int k = snprintf(out + n, out_cap - n, "))");
  if (k < 0 || (size_t)k >= out_cap - n) return false;
  n += (size_t)k;
  char cs[9];
  if (!desc_checksum(out, cs)) return false;
  if (checksum_out) memcpy(checksum_out, cs, 9);
  k = snprintf(out + n, out_cap - n, "#%s", cs);
  return k > 0 && (size_t)k < out_cap - n;
}

static bool ms_key_expr(const uint8_t fp[4], const bip32_xpub *xpub, char *out, size_t out_cap) {
  char xs[128];
  if (!ms_xpub_to_string(xpub, MS_VER_XPUB, xs, sizeof(xs))) return false;
  int n = snprintf(out, out_cap, "[%02x%02x%02x%02x/48h/0h/0h/2h]%s",
                   fp[0], fp[1], fp[2], fp[3], xs);
  return n > 0 && (size_t)n < out_cap;
}

// ── Wallet config parser (Coldcard multisig text format) ───────────────────
//
// This is what Sparrow emits for "Export -> Keystone Multisig -> Show QR"
// (delivered as ur:bytes) and for "Coldcard Multisig" (file). Coldcard,
// Keystone, Passport and Jade all import it.
//
//   Name: My Vault
//   Policy: 2 of 3
//   Derivation: m/48'/0'/0'/2'
//   Format: P2WSH
//
//   73C5DA0A: xpub6E...
//   B8688DF1: xpub6D...
//   28645006: xpub6F...
//
// Rules applied here (V1):
//   - Format must be P2WSH. Derivation (global or per-key) must be BIP-48
//     m/48'/0'/0'/2' — with ' or h. Any other path is refused.
//   - 1 <= m <= n <= MS_MAX_COSIGNERS, and exactly n key lines.
//   - Duplicate fingerprints or duplicate xpubs are refused.
//   - Lines starting with '#' are comments. CRLF tolerated. Keys are
//     case-insensitive; fingerprints are hex in either case.
// `err` (>= 32 bytes) receives a short reason on failure.
static bool ms_parse_path(const char *s, size_t len, uint32_t *path, uint8_t *plen) {
  // "m/48'/0'/0'/2'" or "m/48h/0h/0h/2h" (also accepts leading "m/" absent)
  size_t i = 0; *plen = 0;
  if (len >= 1 && (s[0] == 'm' || s[0] == 'M')) { i = 1; if (i < len && s[i] == '/') i++; }
  while (i < len) {
    uint32_t v = 0; bool any = false;
    while (i < len && s[i] >= '0' && s[i] <= '9') { v = v * 10 + (uint32_t)(s[i] - '0'); i++; any = true; if (v > 0x7FFFFFFF) return false; }
    if (!any) return false;
    if (i < len && (s[i] == '\'' || s[i] == 'h' || s[i] == 'H')) { v |= 0x80000000UL; i++; }
    if (*plen >= MS_PATH_MAX) return false;
    path[(*plen)++] = v;
    if (i < len) { if (s[i] != '/') return false; i++; }
  }
  return *plen > 0;
}

static void ms_trim(const char **p, size_t *n) {
  while (*n && (**p == ' ' || **p == '\t' || **p == '\r')) { (*p)++; (*n)--; }
  while (*n && ((*p)[*n - 1] == ' ' || (*p)[*n - 1] == '\t' || (*p)[*n - 1] == '\r')) (*n)--;
}
static bool ms_key_is(const char *k, size_t kn, const char *name) {
  size_t nn = strlen(name);
  if (kn != nn) return false;
  for (size_t i = 0; i < nn; i++) {
    char a = k[i], b = name[i];
    if (a >= 'A' && a <= 'Z') a += 32;
    if (b >= 'A' && b <= 'Z') b += 32;
    if (a != b) return false;
  }
  return true;
}
static bool ms_hex_fp(const char *s, size_t n, uint8_t fp[4]) {
  if (n != 8) return false;
  for (int i = 0; i < 8; i++) {
    char c = s[i]; uint8_t v;
    if (c >= '0' && c <= '9') v = (uint8_t)(c - '0');
    else if (c >= 'a' && c <= 'f') v = (uint8_t)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') v = (uint8_t)(c - 'A' + 10);
    else return false;
    if (i & 1) fp[i / 2] |= v; else fp[i / 2] = (uint8_t)(v << 4);
  }
  return true;
}

static bool ms_config_parse(const char *text, size_t len, ms_wallet_t *w, char *err) {
  memset(w, 0, sizeof(*w));
  w->our_index = 0xFF;
  uint32_t cur_path[MS_PATH_MAX]; uint8_t cur_plen = 0;
  bool have_policy = false, format_ok = false, have_deriv = false, have_name = false;
  size_t pos = 0;
  while (pos < len) {
    size_t eol = pos;
    while (eol < len && text[eol] != '\n') eol++;
    const char *line = text + pos; size_t ln = eol - pos;
    pos = eol + 1;
    ms_trim(&line, &ln);
    if (ln == 0 || line[0] == '#') continue;
    const char *colon = (const char *)memchr(line, ':', ln);
    if (!colon) { if (err) snprintf(err, 32, "Bad line"); return false; }
    const char *k = line; size_t kn = (size_t)(colon - line);
    const char *v = colon + 1; size_t vn = ln - kn - 1;
    ms_trim(&k, &kn); ms_trim(&v, &vn);

    if (ms_key_is(k, kn, "name")) {
      if (vn == 0) { if (err) snprintf(err, 32, "Empty name"); return false; }
      // 11bl (issue #47 item 9): Name and Policy once each. (Derivation may
      // repeat: Coldcard files give one per cosigner.)
      if (have_name) { if (err) snprintf(err, 32, "Name given twice"); return false; }
      have_name = true;
      size_t c = vn < MS_NAME_LEN - 1 ? vn : MS_NAME_LEN - 1;
      memcpy(w->name, v, c); w->name[c] = 0;
    } else if (ms_key_is(k, kn, "policy")) {
      if (have_policy) { if (err) snprintf(err, 32, "Policy given twice"); return false; }
      unsigned m = 0, n = 0;
      char tmp[24]; size_t c = vn < sizeof(tmp) - 1 ? vn : sizeof(tmp) - 1;
      memcpy(tmp, v, c); tmp[c] = 0;
      if (sscanf(tmp, "%u of %u", &m, &n) != 2 && sscanf(tmp, "%u-of-%u", &m, &n) != 2) {
        if (err) snprintf(err, 32, "Bad policy");
        return false;
      }
      if (m < 1 || n < 1 || m > n || n > MS_MAX_COSIGNERS) { if (err) snprintf(err, 32, "Policy out of range"); return false; }
      w->m = (uint8_t)m; w->n = (uint8_t)n; have_policy = true;
    } else if (ms_key_is(k, kn, "derivation")) {
      if (!ms_parse_path(v, vn, cur_path, &cur_plen)) { if (err) snprintf(err, 32, "Bad derivation"); return false; }
      if (!ms_path_is_bip48(cur_path, cur_plen)) { if (err) snprintf(err, 32, "Path not m/48h/0h/0h/2h"); return false; }
      have_deriv = true;
    } else if (ms_key_is(k, kn, "format")) {
      format_ok = ms_key_is(v, vn, "p2wsh");
      if (!format_ok) { if (err) snprintf(err, 32, "Only P2WSH supported"); return false; }
    } else if (kn == 8) {
      // "XXXXXXXX: xpub..." — a cosigner line
      uint8_t fp[4];
      if (!ms_hex_fp(k, kn, fp)) { if (err) snprintf(err, 32, "Bad fingerprint"); return false; }
      if (!have_deriv) { if (err) snprintf(err, 32, "Derivation before keys"); return false; }
      if (w->n == 0 || !have_policy) { if (err) snprintf(err, 32, "Policy before keys"); return false; }
      // count filled slots
      uint8_t filled = 0; for (int i = 0; i < w->n; i++) if (w->cs[i].path_len) filled++;
      if (filled >= w->n) { if (err) snprintf(err, 32, "Too many keys"); return false; }
      ms_cosigner_t *c = &w->cs[filled];
      if (!ms_xpub_from_string(v, vn, &c->xpub)) {
        if (err) snprintf(err, 32, "Bad xpub (key %u)", (unsigned)filled + 1);
        return false;
      }
      // The BIP-32 depth byte is metadata: nothing in script rebuilding or
      // signing reads it, and coordinators serialise it inconsistently for
      // pasted / software keystores. The trust anchor is key + chain code plus
      // the Derivation line (checked above to be BIP-48). A mismatch is worth
      // knowing about, not worth refusing over — it used to be a hard error and
      // blocked a real Sparrow export on 14 Sep 2026.
      if (c->xpub.depth != MS_BIP48_DEPTH) {
        MS_LOG("[ms] cosigner %u xpub depth %u (expected %u) - accepting\n",
               (unsigned)filled + 1, (unsigned)c->xpub.depth, (unsigned)MS_BIP48_DEPTH);
      }
      for (uint8_t i = 0; i < filled; i++) {
        if (memcmp(w->cs[i].fp, fp, 4) == 0) { if (err) snprintf(err, 32, "Duplicate fingerprint"); return false; }
        if (memcmp(w->cs[i].xpub.pubkey, c->xpub.pubkey, 33) == 0) { if (err) snprintf(err, 32, "Duplicate xpub"); return false; }
      }
      memcpy(c->fp, fp, 4);
      memcpy(c->path, cur_path, sizeof(uint32_t) * cur_plen);
      c->path_len = cur_plen;
    } else {
      // Unknown key (e.g. "Descriptor:") — ignore, as Coldcard does.
    }
  }
  if (!have_policy) { if (err) snprintf(err, 32, "No policy"); return false; }
  if (!format_ok)   { if (err) snprintf(err, 32, "No Format: P2WSH"); return false; }
  uint8_t filled = 0; for (int i = 0; i < w->n; i++) if (w->cs[i].path_len) filled++;
  if (filled != w->n) { if (err) snprintf(err, 32, "Need %u keys, got %u", w->n, filled); return false; }
  if (w->name[0] == 0) snprintf(w->name, MS_NAME_LEN, "%u of %u", w->m, w->n);
  w->valid = 1;
  return true;
}

// Resolve which cosigner is THIS device. Both the fingerprint and the full
// account xpub (pubkey + chain code) must match — a fingerprint alone is 32
// bits and spoofable in a crafted config. Sets w->our_index. Returns false if
// the device is not a member of this wallet (registration must be refused).
static bool ms_wallet_find_ours(ms_wallet_t *w, const uint8_t our_fp[4], const bip32_xpub *our_xpub) {
  w->our_index = 0xFF;
  for (uint8_t i = 0; i < w->n; i++) {
    if (memcmp(w->cs[i].fp, our_fp, 4) == 0 &&
        memcmp(w->cs[i].xpub.pubkey, our_xpub->pubkey, 33) == 0 &&
        memcmp(w->cs[i].xpub.chain_code, our_xpub->chain_code, 32) == 0) {
      w->our_index = i; return true;
    }
  }
  return false;
}

// ── Script construction ────────────────────────────────────────────────────
// Derive every cosigner's leaf pubkey at (change, index) from the REGISTERED
// account xpubs. Two CKD-pub steps each.
static bool ms_derive_pubkeys(const ms_wallet_t *w, uint32_t change, uint32_t index,
                              uint8_t pubs[MS_MAX_COSIGNERS][33]) {
  if (change > 1 || (index & 0x80000000UL)) return false;
  for (uint8_t i = 0; i < w->n; i++) {
    bip32_xpub c, leaf;
    if (!bip32_derive_child_pub(&w->cs[i].xpub, change, &c)) return false;
    if (!bip32_derive_child_pub(&c, index, &leaf)) return false;
    memcpy(pubs[i], leaf.pubkey, 33);
  }
  return true;
}

// sortedmulti witness script: OP_m <pk1>...<pkn> OP_n OP_CHECKMULTISIG with the
// pubkeys in lexicographic order (BIP-67). Returns length or 0.
static size_t ms_build_witness_script(uint8_t m, const uint8_t pubs_in[MS_MAX_COSIGNERS][33], uint8_t n,
                                      uint8_t *out, size_t out_cap) {
  if (m < 1 || n < m || n > MS_MAX_COSIGNERS) return 0;
  size_t need = 1 + (size_t)n * 34 + 2;
  if (need > out_cap) return 0;
  uint8_t sorted[MS_MAX_COSIGNERS][33];
  memcpy(sorted, pubs_in, (size_t)n * 33);
  // insertion sort, n <= 7
  for (uint8_t i = 1; i < n; i++) {
    uint8_t key[33]; memcpy(key, sorted[i], 33);
    int j = (int)i - 1;
    while (j >= 0 && memcmp(sorted[j], key, 33) > 0) { memcpy(sorted[j + 1], sorted[j], 33); j--; }
    memcpy(sorted[j + 1], key, 33);
  }
  size_t p = 0;
  out[p++] = (uint8_t)(0x50 + m);                 // OP_1..OP_16
  for (uint8_t i = 0; i < n; i++) { out[p++] = 0x21; memcpy(out + p, sorted[i], 33); p += 33; }
  out[p++] = (uint8_t)(0x50 + n);
  out[p++] = 0xae;                                // OP_CHECKMULTISIG
  return p;
}

static void ms_p2wsh_spk(const uint8_t *ws, size_t ws_len, uint8_t spk_out[34]) {
  spk_out[0] = 0x00; spk_out[1] = 0x20;
  ms_sha256(ws, ws_len, spk_out + 2);
}

// Rebuild the witness script + scriptPubKey for (change, index) from the
// registered wallet. This is THE trust anchor: anything the PSBT claims about
// a multisig input or output is compared against this.
static bool ms_expected_scripts(const ms_wallet_t *w, uint32_t change, uint32_t index,
                                uint8_t *ws_out, size_t *ws_len_out, uint8_t spk_out[34],
                                uint8_t pubs_out[MS_MAX_COSIGNERS][33]) {
  uint8_t pubs[MS_MAX_COSIGNERS][33];
  if (!ms_derive_pubkeys(w, change, index, pubs)) return false;
  size_t l = ms_build_witness_script(w->m, pubs, w->n, ws_out, PSBT_MAX_WITNESS_SCRIPT);
  if (!l) return false;
  *ws_len_out = l;
  ms_p2wsh_spk(ws_out, l, spk_out);
  if (pubs_out) memcpy(pubs_out, pubs, sizeof(pubs));
  return true;
}

// bc1q... address for (change, index). addr_out >= 96 bytes.
static bool ms_address(const ms_wallet_t *w, uint32_t change, uint32_t index,
                       char *addr_out, size_t cap) {
  if (cap < 96) return false;
  uint8_t ws[PSBT_MAX_WITNESS_SCRIPT]; size_t wl; uint8_t spk[34];
  if (!ms_expected_scripts(w, change, index, ws, &wl, spk, NULL)) return false;
  return segwit_addr_encode("bc", 0, spk + 2, 32, addr_out);
}

// ── Derivation-record checks ───────────────────────────────────────────────
// Given the derivation records a PSBT attached to an input/output, decide
// whether they describe a leaf of THIS wallet, and which one:
//   - exactly n records, none overflowed
//   - every record's fingerprint maps to exactly one registered cosigner
//   - every record's path is m/48'/0'/0'/2'/change/index with the SAME
//     (change,index) for all, change in {0,1}, index unhardened
//   - every record's pubkey equals the pubkey we derive for that cosigner
// Returns true and fills (change, index, our_slot = index into recs that is
// ours, or 0xFF if our fingerprint is absent) on success. pubs_out gets the
// derived pubkeys so the caller can rebuild the script without re-deriving.
static bool ms_match_records(const ms_wallet_t *w, const psbt_bip32_t *recs, uint8_t nrecs, bool overflow,
                             uint32_t *change_out, uint32_t *index_out, uint8_t *our_slot_out,
                             uint8_t pubs_out[MS_MAX_COSIGNERS][33]) {
  if (overflow || nrecs != w->n || nrecs == 0) return false;
  uint32_t change = 0, index = 0;
  uint8_t seen = 0;                       // bitmask of cosigners matched
  uint8_t rec_cs[PSBT_MAX_KEYS];          // record -> cosigner index
  for (uint8_t r = 0; r < nrecs; r++) {
    const psbt_bip32_t *rec = &recs[r];
    if (!rec->present) return false;
    if (rec->path_len != MS_BIP48_DEPTH + 2) return false;
    if (!ms_path_is_bip48(rec->path, MS_BIP48_DEPTH)) return false;
    uint32_t c = rec->path[MS_BIP48_DEPTH], i = rec->path[MS_BIP48_DEPTH + 1];
    if (c > 1 || (i & 0x80000000UL)) return false;
    if (r == 0) { change = c; index = i; }
    else if (c != change || i != index) return false;
    int cs = -1;
    for (uint8_t k = 0; k < w->n; k++) if (memcmp(w->cs[k].fp, rec->fingerprint, 4) == 0) { cs = k; break; }
    if (cs < 0) return false;
    if (seen & (1u << cs)) return false;   // two records for one cosigner
    seen |= (uint8_t)(1u << cs);
    rec_cs[r] = (uint8_t)cs;
  }
  if (index > PSBT_CHANGE_GAP_LIMIT) return false;
  uint8_t pubs[MS_MAX_COSIGNERS][33];
  if (!ms_derive_pubkeys(w, change, index, pubs)) return false;
  uint8_t our_slot = 0xFF;
  for (uint8_t r = 0; r < nrecs; r++) {
    if (memcmp(recs[r].pubkey, pubs[rec_cs[r]], 33) != 0) return false;   // PSBT lied about a cosigner key
    if (rec_cs[r] == w->our_index) our_slot = r;
  }
  *change_out = change; *index_out = index; *our_slot_out = our_slot;
  if (pubs_out) memcpy(pubs_out, pubs, sizeof(pubs));
  return true;
}

// ── Input verification ─────────────────────────────────────────────────────
// True iff the input is provably a leaf of wallet w AND this device is one of
// its cosigners AND we may sign it:
//   (a) witness UTXO present, scriptPubKey is P2WSH
//   (b) derivation records match (ms_match_records) and include us
//   (c) witness script present in the PSBT and EQUAL to the one we rebuild
//   (d) UTXO scriptPubKey == 0x0020 || SHA256(rebuilt script)
//   (e) sighash absent or SIGHASH_ALL
// Fills (change, index) and our leaf pubkey.
static bool ms_verify_input(const ms_wallet_t *w, const psbt_input_t *in,
                            uint32_t *change_out, uint32_t *index_out, uint8_t our_pub_out[33]) {
  if (!w->valid || w->our_index == 0xFF) return false;
  if (!in->witness_utxo_present) return false;
  if (in->witness_utxo_script_len != 34 || in->witness_utxo_script[0] != 0x00 || in->witness_utxo_script[1] != 0x20) return false;
  if (in->sighash_type != 0 && in->sighash_type != 0x01) return false;
  uint32_t change, index; uint8_t our_slot; uint8_t pubs[MS_MAX_COSIGNERS][33];
  if (!ms_match_records(w, in->bip32s, in->n_bip32, in->bip32_overflow, &change, &index, &our_slot, pubs)) return false;
  if (our_slot == 0xFF) return false;
  uint8_t ws[PSBT_MAX_WITNESS_SCRIPT];
  size_t wl = ms_build_witness_script(w->m, pubs, w->n, ws, sizeof(ws));
  if (!wl) return false;
  if (!in->witness_script_present || in->witness_script_len != wl || memcmp(in->witness_script, ws, wl) != 0) return false;
  uint8_t spk[34]; ms_p2wsh_spk(ws, wl, spk);
  if (memcmp(in->witness_utxo_script, spk, 34) != 0) return false;
  *change_out = change; *index_out = index;
  memcpy(our_pub_out, pubs[w->our_index], 33);
  return true;
}

// ── Change output verification ─────────────────────────────────────────────
// True iff the output provably pays a leaf of wallet w. Same rigour as the
// input check. The output witness script is optional in a PSBT; when present
// it must match. The scriptPubKey the coins actually go to MUST match the
// script we rebuild from registered keys — that is the change-redirection
// defence, and it does not care what the PSBT says the script is.
static bool ms_verify_change_output(const ms_wallet_t *w, const psbt_output_t *o, const psbt_txout_t *txout,
                                    uint32_t *change_out, uint32_t *index_out) {
  if (!w->valid) return false;
  if (txout->script_pubkey_len != 34 || txout->script_pubkey[0] != 0x00 || txout->script_pubkey[1] != 0x20) return false;
  uint32_t change, index; uint8_t our_slot; uint8_t pubs[MS_MAX_COSIGNERS][33];
  if (!ms_match_records(w, o->bip32s, o->n_bip32, o->bip32_overflow, &change, &index, &our_slot, pubs)) return false;
  uint8_t ws[PSBT_MAX_WITNESS_SCRIPT];
  size_t wl = ms_build_witness_script(w->m, pubs, w->n, ws, sizeof(ws));
  if (!wl) return false;
  if (o->witness_script_present && (o->witness_script_len != wl || memcmp(o->witness_script, ws, wl) != 0)) return false;
  uint8_t spk[34]; ms_p2wsh_spk(ws, wl, spk);
  if (memcmp(txout->script_pubkey, spk, 34) != 0) return false;
  *change_out = change; *index_out = index;
  return true;
}

// ── PSBT classification ────────────────────────────────────────────────────
// Decide, before anything is displayed, which of our wallets a PSBT spends
// from. One wallet per PSBT.
typedef enum {
  MS_CLASS_SINGLESIG = 0,   // no P2WSH inputs — hand to the BIP-84 path unchanged
  MS_CLASS_MULTISIG  = 1,   // every P2WSH input verifies against ONE registered wallet (*wallet_out)
  MS_CLASS_MIXED     = 2,   // P2WSH inputs AND P2WPKH inputs carrying our fingerprint — refused by policy
  MS_CLASS_NO_WALLET = 3,   // a P2WSH input matches no registered wallet (or two wallets) — "Register wallet first"
  MS_CLASS_NONE_OURS = 4,   // P2WSH inputs present but none includes this device
} ms_class_t;

static ms_class_t ms_classify_psbt(const ms_store_t *store, const psbt_t *psbt, const uint8_t our_fp[4],
                                   int *wallet_out) {
  *wallet_out = -1;
  bool have_wsh = false, have_wpkh_ours = false, any_fp_ours = false;
  int wallet = -1;
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
    const psbt_input_t *in = &psbt->inputs[i];
    if (!in->witness_utxo_present) continue;
    bool wsh  = in->witness_utxo_script_len == 34 && in->witness_utxo_script[0] == 0x00 && in->witness_utxo_script[1] == 0x20;
    bool wpkh = in->witness_utxo_script_len == 22 && in->witness_utxo_script[0] == 0x00 && in->witness_utxo_script[1] == 0x14;
    bool fp_ours = false;
    for (uint8_t r = 0; r < in->n_bip32; r++) if (memcmp(in->bip32s[r].fingerprint, our_fp, 4) == 0) fp_ours = true;
    if (wpkh && fp_ours) have_wpkh_ours = true;
    if (!wsh) continue;
    have_wsh = true;
    if (fp_ours) any_fp_ours = true;
    int match = -1;
    for (int k = 0; k < MS_MAX_WALLETS; k++) {
      uint32_t c, x; uint8_t pub[33];
      if (store->w[k].valid && ms_verify_input(&store->w[k], in, &c, &x, pub)) { match = k; break; }
    }
    if (match < 0) { if (!fp_ours) continue; return MS_CLASS_NO_WALLET; }
    if (wallet >= 0 && wallet != match) return MS_CLASS_NO_WALLET;
    wallet = match;
  }
  if (!have_wsh) return MS_CLASS_SINGLESIG;
  if (have_wpkh_ours) return MS_CLASS_MIXED;
  if (wallet < 0) return any_fp_ours ? MS_CLASS_NO_WALLET : MS_CLASS_NONE_OURS;
  *wallet_out = wallet;
  return MS_CLASS_MULTISIG;
}

// ── Summary for the confirm screen ─────────────────────────────────────────
// Mirrors psbt_build_summary: an output is CHANGE only if it cryptographically
// verifies as a leaf of this wallet; an output whose records carry our
// fingerprint but fails verification is recorded as change-but-UNVERIFIED and
// surfaced (never hidden as a recipient, never shown as safe).
static bool ms_build_summary(const ms_wallet_t *w, const psbt_t *psbt, const uint8_t our_fp[4],
                             psbt_summary_t *sum) {
  memset(sum, 0, sizeof(*sum));
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
    if (!psbt->inputs[i].witness_utxo_present) return false;
    sum->total_in += psbt->inputs[i].witness_utxo_value;
  }
  for (uint8_t i = 0; i < psbt->tx.n_outputs; i++) {
    const psbt_txout_t *out = &psbt->tx.outputs[i];
    const psbt_output_t *o = &psbt->outputs[i];
    bool claims = false;
    for (uint8_t r = 0; r < o->n_bip32; r++) if (memcmp(o->bip32s[r].fingerprint, our_fp, 4) == 0) claims = true;
    if (claims) {
      uint32_t c, x;
      bool ok = ms_verify_change_output(w, o, out, &c, &x);
      uint8_t k = sum->n_changes++;
      sum->changes[k].value = out->value;
      sum->changes[k].script_pubkey_len = out->script_pubkey_len;
      memcpy(sum->changes[k].script_pubkey, out->script_pubkey, out->script_pubkey_len);
      sum->changes[k].verified = ok;
      sum->total_change += out->value;
      if (!ok) sum->n_changes_unverified++;
    } else {
      uint8_t k = sum->n_recipients++;
      sum->recipients[k].value = out->value;
      sum->recipients[k].script_pubkey_len = out->script_pubkey_len;
      memcpy(sum->recipients[k].script_pubkey, out->script_pubkey, out->script_pubkey_len);
      sum->total_recipients += out->value;
    }
  }
  uint64_t total_out = sum->total_recipients + sum->total_change;
  if (total_out > sum->total_in) return false;
  sum->fee = sum->total_in - total_out;
  return true;
}

// ── Signing ────────────────────────────────────────────────────────────────
// Sign every input of `psbt` that verifies against wallet w with our leaf key.
// Returns the number of partial signatures produced, 0 if none verified or
// !approved, -1 on error. Seed-requiring; the caller holds the seed for the
// duration of this call only and zeroises it afterwards (psbtGatedSign does).
// Buffers for the BIP-143 pre-hashes are static: a psbt_t is already ~13KB and
// the loop task stack is not the place for another 2KB.
static int ms_sign_all(const ms_wallet_t *w, const psbt_t *psbt, psbt_g0_sign_fn g0_sign,
                       bool approved, psbt_partial_sig_t *sigs_out, int sigs_cap) {
  if (!approved) return 0;
  if (sigs_cap < 1 || !w->valid || w->our_index == 0xFF || !g0_sign) return -1;

  static bip143_input_t  bin[PSBT_MAX_INPUTS];
  static bip143_output_t bout[PSBT_MAX_OUTPUTS];
  memset(bin, 0, sizeof(bin)); memset(bout, 0, sizeof(bout));
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
    const psbt_txin_t *t = &psbt->tx.inputs[i];
    memcpy(bin[i].outpoint, t->prev_txid, 32);
    bin[i].outpoint[32] = (uint8_t)( t->prev_vout        & 0xFF);
    bin[i].outpoint[33] = (uint8_t)((t->prev_vout >>  8) & 0xFF);
    bin[i].outpoint[34] = (uint8_t)((t->prev_vout >> 16) & 0xFF);
    bin[i].outpoint[35] = (uint8_t)((t->prev_vout >> 24) & 0xFF);
    bin[i].nSequence = t->n_sequence;
  }
  for (uint8_t i = 0; i < psbt->tx.n_outputs; i++) {
    const psbt_txout_t *o = &psbt->tx.outputs[i];
    if ((size_t)o->script_pubkey_len + 1 > sizeof(bout[i].scriptPubKey)) return -1;
    bout[i].value = o->value;
    bout[i].scriptPubKey[0] = o->script_pubkey_len;
    memcpy(bout[i].scriptPubKey + 1, o->script_pubkey, o->script_pubkey_len);
    bout[i].scriptPubKey_len = o->script_pubkey_len + 1;
  }
  uint8_t hashPrevouts[32], hashSequence[32], hashOutputs[32];
  bip143_tx_hashes(bin, psbt->tx.n_inputs, bout, psbt->tx.n_outputs, hashPrevouts, hashSequence, hashOutputs);

  int n_sigs = 0;
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
    const psbt_input_t *in = &psbt->inputs[i];
    uint32_t change, index; uint8_t our_pub[33];
    if (!ms_verify_input(w, in, &change, &index, our_pub)) continue;   // not this wallet's / not ours
    if (n_sigs >= sigs_cap) return -1;

    // Our own sighash, exactly as before.
    static uint8_t scriptCode[BIP143_MAX_SCRIPTCODE];
    size_t scl = bip143_p2wsh_scriptcode(in->witness_script, in->witness_script_len, scriptCode);
    if (!scl) return -1;
    uint8_t sighash[32];
    if (!bip143_input_sighash_sc(psbt->tx.version, psbt->tx.locktime, bin[i].outpoint, bin[i].nSequence,
                                 in->witness_utxo_value, scriptCode, scl,
                                 hashPrevouts, hashSequence, hashOutputs, BIP143_SIGHASH_ALL, sighash)) return -1;

    // v3: the G0 derives m/48'/0'/0'/2'/change/index from the seed IT holds,
    // rebuilds the scriptCode from the witnessScript we pass, recomputes the
    // sighash and signs. The registered xpub says our leaf pubkey is our_pub;
    // the G0's seed must agree (a wallet registered against a different seed
    // must never sign) — and its sighash must equal ours.
    if (in->witness_script_len == 0 || in->witness_script_len > 252) return -1;
    static uint8_t req[416];
    if (!g0_btc_build_request(req, 2, psbt->tx.version, psbt->tx.locktime,
                              hashPrevouts, hashSequence, hashOutputs, bin[i].outpoint,
                              bin[i].nSequence, in->witness_utxo_value, change, index,
                              in->witness_script, in->witness_script_len)) return -1;
    uint8_t pub[33], der[72], dl = 0, sh[32];
    bool ok = g0_sign(req, pub, der, &dl, sh);
    memset(req, 0, sizeof(req));
    if (!ok) return -1;
    if (memcmp(pub, our_pub, 33) != 0) { MS_LOG("[ms] G0 leaf pubkey != registered cosigner pubkey at %lu/%lu - refusing\n", (unsigned long)change, (unsigned long)index); return -1; }
    if (memcmp(sh, sighash, 32) != 0)  { MS_LOG("[ms] G0 sighash != ESP32 sighash for input %u - refusing\n", (unsigned)i); return -1; }
    psbt_partial_sig_t *out = &sigs_out[n_sigs++];
    out->input_index = i;
    memcpy(out->pubkey, our_pub, 33);
    memcpy(out->der, der, dl);
    out->der_len = dl;
    out->sighash_type = BIP143_SIGHASH_ALL;
  }
  return n_sigs;
}

// ── Scan-to-verify search ──────────────────────────────────────────────────
// Find which (change, index) a scriptPubKey belongs to, searching outward
// from `centre` up to `radius` on both chains (0..PSBT_CHANGE_GAP_LIMIT).
// `progress` (optional) is called every 16 indices so the UI can paint a bar
// and feed the watchdog; returning false from it aborts. Returns true on a
// match. Multisig only; the BIP-84 equivalent in Drop 2 follows the same shape.
typedef bool (*ms_progress_fn)(uint32_t done, uint32_t total);
static bool ms_search_spk(const ms_wallet_t *w, const uint8_t *spk, uint8_t spk_len,
                          uint32_t centre, uint32_t radius,
                          uint32_t *change_out, uint32_t *index_out, ms_progress_fn progress) {
  if (spk_len != 34 || spk[0] != 0x00 || spk[1] != 0x20) return false;
  if (radius > PSBT_CHANGE_GAP_LIMIT) radius = PSBT_CHANGE_GAP_LIMIT;
  uint32_t total = (2 * radius + 1) * 2, done = 0;
  for (uint32_t d = 0; d <= radius; d++) {
    for (int sign = 0; sign < 2; sign++) {
      if (sign == 1 && d == 0) continue;
      int64_t idx = sign ? (int64_t)centre - (int64_t)d : (int64_t)centre + (int64_t)d;
      if (idx < 0 || idx > PSBT_CHANGE_GAP_LIMIT) continue;
      for (uint32_t c = 0; c < 2; c++) {
        uint8_t ws[PSBT_MAX_WITNESS_SCRIPT]; size_t wl; uint8_t e[34];
        if (ms_expected_scripts(w, c, (uint32_t)idx, ws, &wl, e, NULL) && memcmp(e, spk, 34) == 0) {
          *change_out = c; *index_out = (uint32_t)idx; return true;
        }
        if ((++done & 15) == 0 && progress && !progress(done, total)) return false;
      }
    }
  }
  return false;
}

// ── Store helpers (pure; NVS read/write lives in bitcoin_menu.inc) ─────────
static void ms_store_init(ms_store_t *s) { memset(s, 0, sizeof(*s)); s->version = MS_STORE_VERSION; }

static int ms_store_free_slot(const ms_store_t *s) {
  for (int i = 0; i < MS_MAX_WALLETS; i++) if (!s->w[i].valid) return i;
  return -1;
}

// A wallet is "the same" if its sorted set of account pubkeys and threshold
// match, regardless of name or cosigner order. Used to refuse duplicate
// registrations.
static int ms_store_find_same(const ms_store_t *s, const ms_wallet_t *w) {
  for (int i = 0; i < MS_MAX_WALLETS; i++) {
    const ms_wallet_t *x = &s->w[i];
    if (!x->valid || x->m != w->m || x->n != w->n) continue;
    uint8_t seen = 0;
    for (uint8_t a = 0; a < w->n; a++) {
      for (uint8_t b = 0; b < x->n; b++)
        if (!(seen & (1u << b)) && memcmp(x->cs[b].xpub.pubkey, w->cs[a].xpub.pubkey, 33) == 0 &&
            memcmp(x->cs[b].xpub.chain_code, w->cs[a].xpub.chain_code, 32) == 0) { seen |= (uint8_t)(1u << b); break; }
    }
    if (seen == (uint8_t)((1u << x->n) - 1)) return i;
  }
  return -1;
}

static bool ms_store_add(ms_store_t *s, const ms_wallet_t *w) {
  if (!w->valid || w->our_index == 0xFF) return false;
  if (ms_store_find_same(s, w) >= 0) return false;
  int slot = ms_store_free_slot(s);
  if (slot < 0) return false;
  s->w[slot] = *w;
  s->count++;
  return true;
}

static void ms_store_remove(ms_store_t *s, int slot) {
  if (slot < 0 || slot >= MS_MAX_WALLETS || !s->w[slot].valid) return;
  memset(&s->w[slot], 0, sizeof(ms_wallet_t));
  if (s->count) s->count--;
}

// ══════════════════════════════════════════════════════════════════════════
// Address decode (scan-to-verify) — bech32 / bech32m -> scriptPubKey
// ══════════════════════════════════════════════════════════════════════════
// bech32.h is encode-only. Accepts "bc1..." (either case, not mixed), and a
// "bitcoin:" URI prefix with any query string. Returns spk length or 0.
static int ms_bech32_char(char c) {
  // NOTE: the charset local must NOT be called CS — cipher_game.h does
  // `#define CS CIPHER_CS` and is included before bitcoin_menu.inc, so a
  // plain `CS` here expands to an int and the build fails.
  static const char* MS_BECH32_CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
  const char* p = strchr(MS_BECH32_CS, c);
  return (p && c) ? (int)(p - MS_BECH32_CS) : -1;
}
static uint32_t ms_bech32_polymod(const uint8_t* v, size_t n) {
  static const uint32_t G[5] = { 0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL, 0x2a1462b3UL };
  uint32_t c = 1;
  for (size_t i = 0; i < n; i++) {
    uint8_t c0 = (uint8_t)(c >> 25);
    c = ((c & 0x1ffffffUL) << 5) ^ v[i];
    for (int k = 0; k < 5; k++) if ((c0 >> k) & 1) c ^= G[k];
  }
  return c;
}
static size_t ms_addr_to_spk(const char* in, uint8_t* spk, size_t spk_cap) {
  if (!in) return 0;
  if (strncasecmp(in, "bitcoin:", 8) == 0) in += 8;
  char a[100]; size_t n = 0;
  while (in[n] && in[n] != '?' && n < sizeof(a) - 1) { a[n] = in[n]; n++; }
  a[n] = 0;
  if (n < 8 || n > 90) return 0;
  bool lower = false, upper = false;
  for (size_t i = 0; i < n; i++) { if (a[i] >= 'a' && a[i] <= 'z') lower = true; if (a[i] >= 'A' && a[i] <= 'Z') upper = true; }
  if (lower && upper) return 0;
  const char* sep = strrchr(a, '1');
  if (!sep || sep == a || (size_t)(sep - a) != 2 || n - (size_t)(sep - a) - 1 < 7) return 0;
  if (!((a[0] == 'b' || a[0] == 'B') && (a[1] == 'c' || a[1] == 'C'))) return 0;
  size_t dlen = n - 3;
  uint8_t v[96]; size_t vn = 0;
  v[vn++] = 'b' >> 5; v[vn++] = 'c' >> 5; v[vn++] = 0; v[vn++] = 'b' & 31; v[vn++] = 'c' & 31;
  uint8_t data[90];
  for (size_t i = 0; i < dlen; i++) { int d = ms_bech32_char(a[3 + i]); if (d < 0) return 0; data[i] = (uint8_t)d; v[vn++] = (uint8_t)d; }
  uint32_t pm = ms_bech32_polymod(v, vn);
  int witver = data[0];
  if (witver == 0 && pm != 1) return 0;
  if (witver != 0 && pm != 0x2bc830a3UL) return 0;   // bech32m
  if (witver > 16) return 0;
  // convert 5-bit groups (excluding version and 6 checksum chars) to 8-bit
  uint8_t prog[40]; size_t pn = 0; uint32_t acc = 0; int bits = 0;
  for (size_t i = 1; i + 6 < dlen; i++) {
    acc = (acc << 5) | data[i]; bits += 5;
    while (bits >= 8) { bits -= 8; if (pn >= sizeof(prog)) return 0; prog[pn++] = (uint8_t)((acc >> bits) & 0xFF); }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xFF)) return 0;   // padding rules
  if (pn < 2 || pn > 40) return 0;
  if (witver == 0 && pn != 20 && pn != 32) return 0;
  if (spk_cap < pn + 2) return 0;
  spk[0] = witver == 0 ? 0x00 : (uint8_t)(0x50 + witver);
  spk[1] = (uint8_t)pn;
  memcpy(spk + 2, prog, pn);
  return pn + 2;
}

// ══════════════════════════════════════════════════════════════════════════
// Cosigner export — UR crypto-account (BCR-2020-015) CBOR body
// ══════════════════════════════════════════════════════════════════════════
// What Keystone / Passport / Cobo show for "export xpub" and what Sparrow's
// Airgapped Hardware Wallet -> Scan reads. One QR carries BOTH our keys, so
// Sparrow picks whichever its wallet needs:
//   wpkh(hdkey m/84'/0'/0')      single-sig     (tag 404)   — optional, may be NULL
//   wsh(hdkey m/48'/0'/0'/2')    P2WSH multisig (tag 401)
// Layout: {1: master-fp uint32, 2: [ 404(303{...}), 401(303{...}) ]}
// hdkey (303): {3: key-data bstr33, 4: chain-code bstr32,
//               6: keypath 304({1: [i,hardened,...], 2: master-fp uint32, 3: depth}),
//               8: parent-fp uint32}
// Returns CBOR length or 0.
static size_t ms_cbor_u32(uint8_t* o, uint32_t v) {
  if (v < 24)          { o[0] = (uint8_t)v; return 1; }
  if (v <= 0xFF)       { o[0] = 0x18; o[1] = (uint8_t)v; return 2; }
  if (v <= 0xFFFF)     { o[0] = 0x19; o[1] = v >> 8; o[2] = v & 0xFF; return 3; }
  o[0] = 0x1a; o[1] = v >> 24; o[2] = (v >> 16) & 0xFF; o[3] = (v >> 8) & 0xFF; o[4] = v & 0xFF; return 5;
}
static size_t ms_cbor_tag(uint8_t* o, uint32_t t) {
  // tag major type 6: same length encoding as uint, with 0xC0 base
  size_t n = ms_cbor_u32(o, t); o[0] |= 0xC0; return n;
}
static size_t ms_cbor_hdkey(uint8_t* o, const bip32_xpub* x, const uint32_t* path, uint8_t plen,
                            uint32_t master_fp, uint32_t out_tag) {
  size_t p = 0;
  p += ms_cbor_tag(o + p, out_tag);          // 404 wpkh / 401 wsh
  p += ms_cbor_tag(o + p, 303);              // crypto-hdkey
  o[p++] = 0xA4;                             // map(4): 3,4,6,8
  o[p++] = 0x03; o[p++] = 0x58; o[p++] = 33; memcpy(o + p, x->pubkey, 33); p += 33;
  o[p++] = 0x04; o[p++] = 0x58; o[p++] = 32; memcpy(o + p, x->chain_code, 32); p += 32;
  o[p++] = 0x06; p += ms_cbor_tag(o + p, 304);
  o[p++] = 0xA3;                             // keypath map(3): 1,2,3
  o[p++] = 0x01; o[p++] = (uint8_t)(0x80 | (plen * 2));   // array(2*plen)
  for (uint8_t i = 0; i < plen; i++) {
    p += ms_cbor_u32(o + p, path[i] & 0x7FFFFFFFUL);
    o[p++] = (path[i] & 0x80000000UL) ? 0xF5 : 0xF4;      // true / false
  }
  o[p++] = 0x02; p += ms_cbor_u32(o + p, master_fp);
  o[p++] = 0x03; p += ms_cbor_u32(o + p, plen);
  o[p++] = 0x08;
  uint32_t pfp = ((uint32_t)x->parent_fingerprint[0] << 24) | ((uint32_t)x->parent_fingerprint[1] << 16) |
                 ((uint32_t)x->parent_fingerprint[2] << 8) | x->parent_fingerprint[3];
  p += ms_cbor_u32(o + p, pfp);
  return p;
}
// Either key may be NULL (at least one required). Coordinators that import a
// COSIGNER (BlueWallet, Keystone-style) want the wsh key ALONE; a single-sig
// import wants the wpkh key alone. Emit one descriptor per QR unless you have
// a specific reason to combine them.
static size_t ms_export_crypto_account(const uint8_t fp[4], const bip32_xpub* xpub84 /*nullable*/,
                                       const bip32_xpub* xpub48 /*nullable*/, uint8_t* out, size_t out_cap) {
  if ((!xpub48 && !xpub84) || out_cap < 320) return 0;
  static const uint32_t P84[3] = { 0x80000054UL, 0x80000000UL, 0x80000000UL };
  uint32_t mfp = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16) | ((uint32_t)fp[2] << 8) | fp[3];
  size_t p = 0;
  out[p++] = 0xA2;                           // map(2): 1 master-fp, 2 descriptors
  out[p++] = 0x01; p += ms_cbor_u32(out + p, mfp);
  out[p++] = 0x02; out[p++] = (uint8_t)(0x80 | ((xpub84 ? 1 : 0) + (xpub48 ? 1 : 0)));
  if (xpub84) p += ms_cbor_hdkey(out + p, xpub84, P84, 3, mfp, 404);
  if (xpub48) p += ms_cbor_hdkey(out + p, xpub48, MS_BIP48_PATH, MS_BIP48_DEPTH, mfp, 401);
  return p;
}
