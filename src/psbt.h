#pragma once
// ============================================================
// psbt.h — BIP-174 PSBT v0 parser for P2WPKH single-sig wallets.
//
// Reads a PSBT (binary, base64 or hex are caller's problem — feed us
// bytes) and fills a psbt_t struct with:
//   - the embedded unsigned tx (version, inputs, outputs, locktime)
//   - per-input: witness UTXO data, BIP32 derivation, sighash type
//   - per-output: BIP32 derivation (used to identify change)
//
// Validated against the same PSBT structure my JS reference parser
// produced against bitcoinjs-lib output. Byte-for-byte equivalent on
// every field tested.
//
// Scope/limits:
//   - PSBT v0 (BIP-174) and v2 (BIP-370).
//   - P2WPKH (BIP-84 single-sig) and P2WSH sortedmulti (BIP-48 multisig, see
//     multisig.h). Witness UTXO required for every input we sign.
//   - MULTISIG (14 Sep 2026): every input/output now keeps ALL of its BIP32
//     derivation records (one per cosigner) in bip32s[]/n_bip32, plus the
//     witness script (PSBT_IN_WITNESS_SCRIPT 0x05 / PSBT_OUT_WITNESS_SCRIPT
//     0x01). The legacy single `bip32` field is kept for the BIP-84 path and
//     always mirrors bip32s[0].
//   - SIGHASH_ALL only (or absent = default SIGHASH_ALL).
//   - Static buffers, no malloc. Hard caps on input/output count and
//     path depth. Reject PSBTs that exceed.
//
// Memory model: a psbt_t was ~2 KB single-sig; with the multisig fields it is
// ~13 KB (8 inputs + 8 outputs, each with 7 derivation records and a 256-byte
// witness script). The firmware keeps ONE static instance (g_pending_psbt);
// do not put a psbt_t on the stack. No heap allocation anywhere.
// ============================================================

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <mbedtls/sha256.h>   // 23 Nov 2026 (#57): txid of PSBT_IN_NON_WITNESS_UTXO

#ifndef PSBT_MAX_INPUTS
#define PSBT_MAX_INPUTS  8
#endif
#ifndef PSBT_MAX_OUTPUTS
#define PSBT_MAX_OUTPUTS 8
#endif
#ifndef PSBT_MAX_SCRIPT_LEN
#define PSBT_MAX_SCRIPT_LEN 40   // P2WPKH=22, P2WSH=34, taproot=34
#endif
#ifndef PSBT_MAX_PATH_DEPTH
#define PSBT_MAX_PATH_DEPTH 8    // BIP-84 uses 5, BIP-48 uses 6, headroom for non-standard
#endif
// Multisig: max BIP32 derivation records kept per input/output (= max
// cosigners, matches MS_MAX_COSIGNERS in multisig.h) and the max witness script
// we accept. A sortedmulti witness script is 1 + 34*N + 2 bytes: 241 at N=7.
#ifndef PSBT_MAX_KEYS
#define PSBT_MAX_KEYS 7
#endif
#ifndef PSBT_MAX_WITNESS_SCRIPT
#define PSBT_MAX_WITNESS_SCRIPT 256
#endif

// ── Parsed structures ────────────────────────────────────────────────

typedef struct {
  uint8_t  prev_txid[32];   // little-endian on the wire
  uint32_t prev_vout;
  uint32_t n_sequence;
} psbt_txin_t;

typedef struct {
  uint64_t value;
  uint8_t  script_pubkey[PSBT_MAX_SCRIPT_LEN];
  uint8_t  script_pubkey_len;
} psbt_txout_t;

typedef struct {
  uint32_t version;
  uint32_t locktime;
  uint8_t  n_inputs;
  uint8_t  n_outputs;
  psbt_txin_t  inputs[PSBT_MAX_INPUTS];
  psbt_txout_t outputs[PSBT_MAX_OUTPUTS];
} psbt_tx_t;

typedef struct {
  uint8_t  pubkey[33];          // compressed pubkey (BIP-84 mandates compressed)
  uint8_t  fingerprint[4];      // master key fingerprint
  uint32_t path[PSBT_MAX_PATH_DEPTH];
  uint8_t  path_len;
  bool     present;
} psbt_bip32_t;

typedef struct {
  // Witness UTXO data (required for any input we sign)
  uint64_t witness_utxo_value;
  uint8_t  witness_utxo_script[PSBT_MAX_SCRIPT_LEN];
  uint8_t  witness_utxo_script_len;
  bool     witness_utxo_present;

  // BIP32 derivation records. Single-sig PSBTs carry one; multisig PSBTs carry
  // one per cosigner. `bip32` mirrors bip32s[0] so the BIP-84 code path is
  // unchanged. bip32_overflow is set (and the parse still succeeds) when more
  // than PSBT_MAX_KEYS records were present — multisig.h refuses such inputs.
  psbt_bip32_t bip32;
  psbt_bip32_t bip32s[PSBT_MAX_KEYS];
  uint8_t      n_bip32;
  bool         bip32_overflow;

  // Witness script (PSBT_IN_WITNESS_SCRIPT 0x05). Required for P2WSH inputs.
  uint8_t  witness_script[PSBT_MAX_WITNESS_SCRIPT];
  uint16_t witness_script_len;
  bool     witness_script_present;

  // Sighash type. 0 = absent (defaults to SIGHASH_ALL = 1).
  uint32_t sighash_type;

  // 23 Nov 2026 (#57, CVE-2020-14199): PSBT_IN_NON_WITNESS_UTXO (0x00), the
  // full previous transaction. psbt_parse hashes it, requires the txid to be
  // this input's prevout, takes output `vout` from it and requires it to equal
  // witness_utxo (or fills witness_utxo from it when that is absent).
  // nwu_verified = the amount and script are proven, not just claimed.
  const uint8_t *nwu_ptr;   // into the caller's buffer, valid during psbt_parse only (cleared before it returns)
  uint32_t nwu_len;
  bool     nwu_verified;
} psbt_input_t;

typedef struct {
  // BIP32 derivation records (used to identify change outputs). Same layout
  // rules as psbt_input_t: `bip32` mirrors bip32s[0].
  psbt_bip32_t bip32;
  psbt_bip32_t bip32s[PSBT_MAX_KEYS];
  uint8_t      n_bip32;
  bool         bip32_overflow;

  // Witness script (PSBT_OUT_WITNESS_SCRIPT 0x01). Present on P2WSH change.
  uint8_t  witness_script[PSBT_MAX_WITNESS_SCRIPT];
  uint16_t witness_script_len;
  bool     witness_script_present;
} psbt_output_t;

typedef struct {
  psbt_tx_t     tx;
  psbt_input_t  inputs[PSBT_MAX_INPUTS];
  psbt_output_t outputs[PSBT_MAX_OUTPUTS];
  uint8_t       psbt_version;   // 0 = PSBTv0 (BIP-174), 2 = PSBTv2 (BIP-370)
} psbt_t;

// ── Reader: bounded read with EOF detection ──────────────────────────
//
// Every read checks remaining bytes. On EOF, every function bails out
// with false — propagates up to the top-level parse call.

typedef struct {
  const uint8_t *buf;
  size_t         len;
  size_t         pos;
} psbt_reader_t;

static inline bool psbt_r_byte(psbt_reader_t *r, uint8_t *out) {
  if (r->pos >= r->len) return false;
  *out = r->buf[r->pos++];
  return true;
}
// 24 Nov 2026 (#67): every bound below is `n > len - pos`, never `pos + n > len`.
// pos <= len always holds, so the subtraction cannot wrap; the sum could, on the
// ESP32's 32-bit size_t, and a wrapped sum moved pos backwards.
static inline bool psbt_r_bytes(psbt_reader_t *r, uint8_t *out, size_t n) {
  if (n > r->len - r->pos) return false;
  memcpy(out, r->buf + r->pos, n);
  r->pos += n;
  return true;
}
static inline bool psbt_r_skip(psbt_reader_t *r, size_t n) {
  if (n > r->len - r->pos) return false;
  r->pos += n;
  return true;
}
static inline const uint8_t *psbt_r_view(psbt_reader_t *r, size_t n) {
  // Returns a pointer into the buffer without copying. Caller must not
  // use it past the next read. Useful when peeking at sub-structures.
  if (n > r->len - r->pos) return NULL;
  const uint8_t *p = r->buf + r->pos;
  r->pos += n;
  return p;
}

// Compact size unsigned int. BIP-174 mandates minimal encoding.
static bool psbt_r_varint(psbt_reader_t *r, uint64_t *out) {
  uint8_t first;
  if (!psbt_r_byte(r, &first)) return false;
  if (first < 0xfd) { *out = first; return true; }
  if (first == 0xfd) {
    uint8_t lo, hi;
    if (!psbt_r_byte(r, &lo) || !psbt_r_byte(r, &hi)) return false;
    uint32_t v = lo | ((uint32_t)hi << 8);
    if (v < 0xfd) return false;        // non-minimal
    *out = v; return true;
  }
  if (first == 0xfe) {
    uint8_t b[4];
    if (!psbt_r_bytes(r, b, 4)) return false;
    uint32_t v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                 ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    if (v <= 0xffff) return false;     // non-minimal
    *out = v; return true;
  }
  // 0xff = 8-byte form. Not expected for PSBTs we handle (16KB max).
  return false;
}

static bool psbt_r_u32le(psbt_reader_t *r, uint32_t *out) {
  uint8_t b[4];
  if (!psbt_r_bytes(r, b, 4)) return false;
  *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
         ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
  return true;
}
static bool psbt_r_u64le(psbt_reader_t *r, uint64_t *out) {
  uint8_t b[8];
  if (!psbt_r_bytes(r, b, 8)) return false;
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
  *out = v;
  return true;
}

// ── Unsigned tx parser ───────────────────────────────────────────────
//
// Format (network serialization, no witness data since PSBT unsigned tx
// must have empty scriptSigs):
//   4-byte version LE
//   varint n_inputs
//   for each input: 32-byte txid + 4-byte vout LE + varint scriptSig_len
//                   + scriptSig (must be empty) + 4-byte nSequence LE
//   varint n_outputs
//   for each output: 8-byte value LE + varint scriptPubKey_len + scriptPubKey
//   4-byte locktime LE
static bool psbt_parse_unsigned_tx(const uint8_t *buf, size_t len, psbt_tx_t *tx) {
  psbt_reader_t r = { buf, len, 0 };

  if (!psbt_r_u32le(&r, &tx->version)) return false;

  uint64_t n_in;
  if (!psbt_r_varint(&r, &n_in)) return false;
  if (n_in == 0 || n_in > PSBT_MAX_INPUTS) return false;
  tx->n_inputs = (uint8_t)n_in;

  for (uint64_t i = 0; i < n_in; i++) {
    psbt_txin_t *in = &tx->inputs[i];
    if (!psbt_r_bytes(&r, in->prev_txid, 32)) return false;
    if (!psbt_r_u32le(&r, &in->prev_vout)) return false;
    uint64_t ss_len;
    if (!psbt_r_varint(&r, &ss_len)) return false;
    // BIP-174: PSBT unsigned tx must have empty scriptSigs
    if (ss_len != 0) return false;
    if (!psbt_r_u32le(&r, &in->n_sequence)) return false;
  }

  uint64_t n_out;
  if (!psbt_r_varint(&r, &n_out)) return false;
  if (n_out == 0 || n_out > PSBT_MAX_OUTPUTS) return false;
  tx->n_outputs = (uint8_t)n_out;

  for (uint64_t i = 0; i < n_out; i++) {
    psbt_txout_t *out = &tx->outputs[i];
    if (!psbt_r_u64le(&r, &out->value)) return false;
    uint64_t spk_len;
    if (!psbt_r_varint(&r, &spk_len)) return false;
    if (spk_len > PSBT_MAX_SCRIPT_LEN) return false;
    if (!psbt_r_bytes(&r, out->script_pubkey, spk_len)) return false;
    out->script_pubkey_len = (uint8_t)spk_len;
  }

  if (!psbt_r_u32le(&r, &tx->locktime)) return false;
  if (r.pos != r.len) return false;     // trailing data is invalid
  return true;
}

// ── BIP32 derivation parser ──────────────────────────────────────────
//
// Format (within PSBT_IN_BIP32_DERIVATION or PSBT_OUT_BIP32_DERIVATION):
//   keydata = pubkey (33 bytes compressed)
//   value = fingerprint (4 bytes) || path elements (4 bytes each)
static bool psbt_parse_bip32(const uint8_t *keydata, size_t keylen,
                              const uint8_t *value, size_t vallen,
                              psbt_bip32_t *out) {
  // Pubkey must be 33-byte compressed (0x02 or 0x03 prefix).
  if (keylen != 33) return false;
  if (keydata[0] != 0x02 && keydata[0] != 0x03) return false;
  memcpy(out->pubkey, keydata, 33);

  // Value: 4-byte fp + N×4 path elements
  if (vallen < 4 || (vallen - 4) % 4 != 0) return false;
  size_t path_count = (vallen - 4) / 4;
  if (path_count > PSBT_MAX_PATH_DEPTH) return false;
  memcpy(out->fingerprint, value, 4);
  for (size_t i = 0; i < path_count; i++) {
    const uint8_t *p = value + 4 + i * 4;
    out->path[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                   ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  }
  out->path_len = (uint8_t)path_count;
  out->present = true;
  return true;
}

// Append one derivation record to an input/output's list. Duplicate pubkeys
// are rejected (BIP-174 forbids duplicate keys). Overflow is recorded, not
// fatal: the single-sig path only needs bip32s[0], and the multisig path
// checks bip32_overflow itself.
static bool psbt_bip32_append(psbt_bip32_t *list, uint8_t *n, bool *overflow,
                              psbt_bip32_t *first,
                              const uint8_t *keydata, size_t keylen,
                              const uint8_t *value, size_t vallen) {
  psbt_bip32_t rec;
  memset(&rec, 0, sizeof(rec));
  if (!psbt_parse_bip32(keydata, keylen, value, vallen, &rec)) return false;
  for (uint8_t i = 0; i < *n; i++)
    if (memcmp(list[i].pubkey, rec.pubkey, 33) == 0) return false;   // duplicate key
  if (*n >= PSBT_MAX_KEYS) { *overflow = true; return true; }
  list[*n] = rec;
  if (*n == 0) *first = rec;
  (*n)++;
  return true;
}

// Witness script (0x05 input / 0x01 output). Bounded copy; a script we cannot
// hold is a parse failure — silently truncating a script would let a crafted
// PSBT make an oversized script look like a short one.
static bool psbt_parse_witness_script(const uint8_t *value, size_t vallen,
                                      uint8_t *out, uint16_t *out_len, bool *present) {
  if (vallen == 0 || vallen > PSBT_MAX_WITNESS_SCRIPT) return false;
  if (*present) return false;   // duplicate key
  memcpy(out, value, vallen);
  *out_len = (uint16_t)vallen;
  *present = true;
  return true;
}

// ── Witness UTXO parser ──────────────────────────────────────────────
//
// Format: 8-byte value LE + varint scriptPubKey_len + scriptPubKey
static bool psbt_parse_witness_utxo(const uint8_t *value, size_t vallen,
                                     psbt_input_t *in) {
  psbt_reader_t r = { value, vallen, 0 };
  if (!psbt_r_u64le(&r, &in->witness_utxo_value)) return false;
  uint64_t spk_len;
  if (!psbt_r_varint(&r, &spk_len)) return false;
  if (spk_len > PSBT_MAX_SCRIPT_LEN) return false;
  if (!psbt_r_bytes(&r, in->witness_utxo_script, spk_len)) return false;
  in->witness_utxo_script_len = (uint8_t)spk_len;
  if (r.pos != r.len) return false;
  in->witness_utxo_present = true;
  return true;
}

// ── Map reader: iterate keypairs until 0x00 separator ────────────────
//
// PSBT global/input/output maps all share this structure:
//   keypair = varint keylen + keylen bytes (first = keytype) +
//             varint vallen + vallen bytes
//   Map ends at a keylen byte = 0x00 (i.e. varint 0).
//
// The callback receives (keytype, keydata, keydatalen, value, vallen)
// and the user_data pointer. Returning false from the callback aborts
// the parse.
typedef bool (*psbt_map_cb)(uint8_t keytype,
                            const uint8_t *keydata, size_t keylen,
                            const uint8_t *value,   size_t vallen,
                            void *user_data);

static bool psbt_read_map(psbt_reader_t *r, psbt_map_cb cb, void *user_data) {
  for (;;) {
    uint64_t keylen;
    if (!psbt_r_varint(r, &keylen)) return false;
    if (keylen == 0) return true;     // 0x00 separator ends map
    // BIP-174 v0 keys fit in <64B, but PSBT_GLOBAL_XPUB (0x01) carries a
    // 78-byte serialized xpub as KEY data → 79-byte key. Real wallet PSBTs
    // (Sparrow et al.) include it. Raise the cap so the map reader doesn't
    // reject the whole PSBT; the xpub itself is ignored in psbt_global_cb.
    if (keylen > 128) return false;
    const uint8_t *keybuf = psbt_r_view(r, keylen);
    if (!keybuf) return false;
    uint8_t keytype = keybuf[0];
    const uint8_t *keydata = keybuf + 1;
    size_t keydata_len = keylen - 1;

    uint64_t vallen;
    if (!psbt_r_varint(r, &vallen)) return false;
    // 24 Nov 2026 (#67): a value is a view into the buffer, never copied, so its
    // only real bound is the bytes left. Test that before any cast to size_t
    // (32 bits on the ESP32). Key 0x00 (an input's NON_WITNESS_UTXO, the whole
    // previous transaction; the global unsigned tx) may be as long as the PSBT:
    // real previous transactions are often over 1 KB. Every other value keeps
    // the old 1024-byte sanity bound (witness UTXOs are under 100 bytes).
    if (vallen > (uint64_t)(r->len - r->pos)) return false;
    if (keytype != 0x00 && vallen > 1024) return false;
    const uint8_t *value = psbt_r_view(r, vallen);
    if (!value) return false;

    if (!cb(keytype, keydata, keydata_len, value, vallen, user_data)) return false;
  }
}

// ── Per-map callbacks ────────────────────────────────────────────────

typedef struct {
  psbt_t *psbt;
  const uint8_t *unsigned_tx_buf;
  size_t         unsigned_tx_len;
  bool           has_unsigned_tx;
  // PSBTv2 (BIP-370) globals. In v2 there is no unsigned-tx blob; the tx
  // version / input count / output count / locktime live as discrete keys.
  uint32_t       version;        // value from 0xfb (0 or 2)
  bool           has_version;
  uint32_t       v2_tx_version;  // 0x02 PSBT_GLOBAL_TX_VERSION
  bool           has_v2_tx_version;
  uint32_t       v2_locktime;    // 0x03 PSBT_GLOBAL_FALLBACK_LOCKTIME (optional)
  uint64_t       v2_in_count;    // 0x04 PSBT_GLOBAL_INPUT_COUNT
  bool           has_v2_in_count;
  uint64_t       v2_out_count;   // 0x05 PSBT_GLOBAL_OUTPUT_COUNT
  bool           has_v2_out_count;
} psbt_global_ctx_t;

static bool psbt_global_cb(uint8_t keytype,
                           const uint8_t *keydata, size_t keylen,
                           const uint8_t *value,   size_t vallen,
                           void *user_data) {
  psbt_global_ctx_t *ctx = (psbt_global_ctx_t *)user_data;
  switch (keytype) {
    case 0x00:  // PSBT_GLOBAL_UNSIGNED_TX (required for v0, forbidden in v2)
      if (keylen != 0) return false;
      if (ctx->has_unsigned_tx) return false;  // duplicate
      ctx->unsigned_tx_buf = value;
      ctx->unsigned_tx_len = vallen;
      ctx->has_unsigned_tx = true;
      return true;
    case 0x02:  // PSBT_GLOBAL_TX_VERSION (v2)
      if (keylen != 0 || vallen != 4) return false;
      ctx->v2_tx_version = (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
                           ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
      ctx->has_v2_tx_version = true;
      return true;
    case 0x03:  // PSBT_GLOBAL_FALLBACK_LOCKTIME (v2, optional)
      if (keylen != 0 || vallen != 4) return false;
      ctx->v2_locktime = (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
                         ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
      return true;
    case 0x04:  // PSBT_GLOBAL_INPUT_COUNT (v2) — compact size in value
      if (keylen != 0) return false;
      { psbt_reader_t vr = { value, vallen, 0 };
        if (!psbt_r_varint(&vr, &ctx->v2_in_count)) return false; }
      ctx->has_v2_in_count = true;
      return true;
    case 0x05:  // PSBT_GLOBAL_OUTPUT_COUNT (v2) — compact size in value
      if (keylen != 0) return false;
      { psbt_reader_t vr = { value, vallen, 0 };
        if (!psbt_r_varint(&vr, &ctx->v2_out_count)) return false; }
      ctx->has_v2_out_count = true;
      return true;
    case 0xfb: {  // PSBT_GLOBAL_VERSION — 0 (v0) or 2 (v2) supported
      if (vallen != 4) return false;
      uint32_t v = (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
                   ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
      if (v != 0 && v != 2) return false;  // refuse v1 / unknown
      ctx->version = v;
      ctx->has_version = true;
      return true;
    }
    default:
      // Unknown globals (0x01 xpub, 0xfc proprietary, etc.): ignored.
      // BIP-174 says we MUST pass-through when re-serializing, but for
      // V1 we just ignore — re-serialization happens via a fresh build.
      return true;
  }
}

typedef struct {
  psbt_input_t *input;
  psbt_txin_t  *txin;     // v2: per-input txid/vout/sequence land here
  bool          is_v2;
} psbt_input_ctx_t;

static bool psbt_input_cb(uint8_t keytype,
                          const uint8_t *keydata, size_t keylen,
                          const uint8_t *value,   size_t vallen,
                          void *user_data) {
  psbt_input_ctx_t *ctx = (psbt_input_ctx_t *)user_data;
  switch (keytype) {
    case 0x00:  // PSBT_IN_NON_WITNESS_UTXO (#57): checked against the prevout at the end of psbt_parse
      if (keylen != 0 || vallen == 0 || ctx->input->nwu_ptr) return false;   // one per input
      ctx->input->nwu_ptr = value; ctx->input->nwu_len = (uint32_t)vallen;
      return true;
    case 0x01:  // PSBT_IN_WITNESS_UTXO
      if (keylen != 0) return false;
      return psbt_parse_witness_utxo(value, vallen, ctx->input);
    case 0x02:  // PSBT_IN_PARTIAL_SIG — we IGNORE incoming sigs (we'll add our own)
      return true;
    case 0x03:  // PSBT_IN_SIGHASH_TYPE
      if (keylen != 0 || vallen != 4) return false;
      ctx->input->sighash_type = (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
                                  ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
      return true;
    case 0x05:  // PSBT_IN_WITNESS_SCRIPT (multisig)
      if (keylen != 0) return false;
      return psbt_parse_witness_script(value, vallen, ctx->input->witness_script,
                                       &ctx->input->witness_script_len,
                                       &ctx->input->witness_script_present);
    case 0x06:  // PSBT_IN_BIP32_DERIVATION (one per cosigner in multisig)
      return psbt_bip32_append(ctx->input->bip32s, &ctx->input->n_bip32,
                               &ctx->input->bip32_overflow, &ctx->input->bip32,
                               keydata, keylen, value, vallen);
    case 0x0e:  // PSBT_IN_PREVIOUS_TXID (v2) — 32 bytes, little-endian on wire
      if (!ctx->is_v2 || keylen != 0 || vallen != 32) return false;
      memcpy(ctx->txin->prev_txid, value, 32);
      return true;
    case 0x0f:  // PSBT_IN_OUTPUT_INDEX (v2) — 4-byte LE vout
      if (!ctx->is_v2 || keylen != 0 || vallen != 4) return false;
      ctx->txin->prev_vout = (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
                             ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
      return true;
    case 0x10:  // PSBT_IN_SEQUENCE (v2) — 4-byte LE; absent defaults to 0xffffffff
      if (!ctx->is_v2 || keylen != 0 || vallen != 4) return false;
      ctx->txin->n_sequence = (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
                              ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
      return true;
    default:
      // Unknown input keys: ignored (signer is required to ignore unknown
      // keys per BIP-174, though must pass them through on serialization).
      return true;
  }
}

typedef struct {
  psbt_output_t *output;
  psbt_txout_t  *txout;    // v2: per-output amount/script land here
  bool           is_v2;
} psbt_output_ctx_t;

static bool psbt_output_cb(uint8_t keytype,
                           const uint8_t *keydata, size_t keylen,
                           const uint8_t *value,   size_t vallen,
                           void *user_data) {
  psbt_output_ctx_t *ctx = (psbt_output_ctx_t *)user_data;
  switch (keytype) {
    case 0x01:  // PSBT_OUT_WITNESS_SCRIPT (multisig change)
      if (keylen != 0) return false;
      return psbt_parse_witness_script(value, vallen, ctx->output->witness_script,
                                       &ctx->output->witness_script_len,
                                       &ctx->output->witness_script_present);
    case 0x02:  // PSBT_OUT_BIP32_DERIVATION (one per cosigner in multisig)
      return psbt_bip32_append(ctx->output->bip32s, &ctx->output->n_bip32,
                               &ctx->output->bip32_overflow, &ctx->output->bip32,
                               keydata, keylen, value, vallen);
    case 0x03:  // PSBT_OUT_AMOUNT (v2) — 8-byte LE sats
      if (!ctx->is_v2 || keylen != 0 || vallen != 8) return false;
      { uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)value[i] << (8 * i);
        ctx->txout->value = v; }
      return true;
    case 0x04:  // PSBT_OUT_SCRIPT (v2) — scriptPubKey bytes
      if (!ctx->is_v2 || keylen != 0) return false;
      if (vallen > PSBT_MAX_SCRIPT_LEN) return false;
      memcpy(ctx->txout->script_pubkey, value, vallen);
      ctx->txout->script_pubkey_len = (uint8_t)vallen;
      return true;
    default:
      return true;
  }
}

// ── Diagnostic: last-failure reason code ─────────────────────────────
// psbt_parse writes a specific code here on every failure path so the
// firmware can print WHICH check failed instead of a bare "parse failed".
// Read psbt_last_err after a false return. Codes are stable; see strings.
static int psbt_last_err = 0;
static const char* psbt_err_str(int e) {
  switch (e) {
    case 0:  return "ok";
    case 1:  return "null/short buf";
    case 2:  return "bad magic";
    case 3:  return "global map read";
    case 4:  return "no version marker";
    case 5:  return "v0 no unsigned tx";
    case 6:  return "v0 unsigned-tx parse";
    case 7:  return "v0 input map";
    case 8:  return "v0 output map";
    case 9:  return "v2 has unsigned tx";
    case 10: return "v2 no tx version";
    case 11: return "v2 no in/out count";
    case 12: return "v2 in-count range";
    case 13: return "v2 out-count range";
    case 14: return "v2 input map";
    case 15: return "v2 output map";
    case 16: return "v2 output no script";
    case 17: return "trailing bytes";
    case 18: return "amount above 21M BTC";
    case 19: return "previous tx does not match";
    case 20: return "witness UTXO contradicts previous tx";
    default: return "unknown";
  }
}
#define PSBT_FAIL(c) do { psbt_last_err = (c); return false; } while (0)

// ── Top-level parse ──────────────────────────────────────────────────
//
// Caller passes the raw PSBT bytes (already base64-decoded if applicable)
// and a psbt_t to fill. Returns true on success, false on any
// malformed/unsupported PSBT. On failure the psbt_t contents are
// undefined — caller must not use it.
#define PSBT_MAX_MONEY 2100000000000000ULL   // 21e6 BTC in sats

// 23 Nov 2026 (#57): read a previous transaction (network serialisation, with
// or without witness), compute its txid (double SHA-256 of the serialisation
// WITHOUT marker, flag and witnesses) and pick output `vout`. True only when
// the txid equals `want_txid` and output `vout` exists and its script fits.
static bool psbt_prev_tx_check(const uint8_t *tx, size_t len, const uint8_t want_txid[32],
                               uint32_t vout, uint64_t *value, uint8_t *spk, uint8_t *spk_len) {
  psbt_reader_t r = { tx, len, 0 };
  // 24 Nov 2026 (#67): every script and witness length is checked against the
  // bytes left (len - r.pos) while still 64 bits, before the cast to size_t.
  if (!psbt_r_skip(&r, 4)) return false;                 // version
  size_t ver_end = r.pos;
  bool segwit = false;
  if (len - r.pos >= 2 && tx[r.pos] == 0x00) {           // marker 0x00, flag 0x01
    if (tx[r.pos + 1] != 0x01) return false;
    segwit = true; r.pos += 2;
  }
  size_t body_start = r.pos;
  uint64_t n_in, n_out;
  if (!psbt_r_varint(&r, &n_in) || n_in == 0 || n_in > len / 41) return false;
  for (uint64_t i = 0; i < n_in; i++) {
    uint64_t sl;
    if (!psbt_r_skip(&r, 36) || !psbt_r_varint(&r, &sl) || sl > len - r.pos || !psbt_r_skip(&r, (size_t)sl) || !psbt_r_skip(&r, 4)) return false;
  }
  if (!psbt_r_varint(&r, &n_out) || n_out == 0 || n_out > len / 9) return false;
  bool found = false;
  for (uint64_t i = 0; i < n_out; i++) {
    uint64_t v, sl;
    if (!psbt_r_u64le(&r, &v) || !psbt_r_varint(&r, &sl) || sl > len - r.pos) return false;   // #67: before any cast
    if (i == vout) {
      if (sl > PSBT_MAX_SCRIPT_LEN || !psbt_r_bytes(&r, spk, (size_t)sl)) return false;
      *value = v; *spk_len = (uint8_t)sl; found = true;
    } else if (!psbt_r_skip(&r, (size_t)sl)) return false;
  }
  size_t body_end = r.pos;
  if (segwit) {
    for (uint64_t i = 0; i < n_in; i++) {
      uint64_t items;
      if (!psbt_r_varint(&r, &items) || items > len) return false;
      for (uint64_t k = 0; k < items; k++) {
        uint64_t il;
        if (!psbt_r_varint(&r, &il) || il > len - r.pos || !psbt_r_skip(&r, (size_t)il)) return false;   // #67
      }
    }
  }
  if (!psbt_r_skip(&r, 4) || r.pos != len) return false;  // locktime, nothing after
  if (!found || body_end < body_start || body_end > len) return false;   // #67: never hash a wrapped span
  uint8_t h[32];
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, tx, ver_end);
  mbedtls_sha256_update(&c, tx + body_start, body_end - body_start);
  mbedtls_sha256_update(&c, tx + len - 4, 4);
  mbedtls_sha256_finish(&c, h); mbedtls_sha256_free(&c);
  mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, h, 32);
  mbedtls_sha256_finish(&c, h); mbedtls_sha256_free(&c);
  return memcmp(h, want_txid, 32) == 0;
}

// 23 Nov 2026 (#57): the BIP-143 fee attack needs two inputs whose amounts the
// coordinator can lie about in separate signing rounds. So a transaction with
// two or more inputs is signed only when every input's amount is proven by its
// full previous transaction (nwu_verified). One input: a lie only makes an
// invalid signature, so witness_utxo alone is accepted.
static bool psbt_amounts_proven(const psbt_t *psbt) {
  if (psbt->tx.n_inputs < 2) return true;
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++)
    if (!psbt->inputs[i].nwu_verified) return false;
  return true;
}
static bool psbt_parse(const uint8_t *buf, size_t len, psbt_t *psbt) {
  psbt_last_err = 0;
  if (!buf || !psbt || len < 5) PSBT_FAIL(1);

  // Zero everything — partial parses become detectable as `.present = false`
  memset(psbt, 0, sizeof(*psbt));

  psbt_reader_t r = { buf, len, 0 };

  // Magic: "psbt\xff" = 0x70 0x73 0x62 0x74 0xff
  static const uint8_t MAGIC[5] = { 0x70, 0x73, 0x62, 0x74, 0xff };
  const uint8_t *m = psbt_r_view(&r, 5);
  if (!m || memcmp(m, MAGIC, 5) != 0) PSBT_FAIL(2);

  // Global map → captures unsigned tx buffer (v0) or v2 globals
  psbt_global_ctx_t gctx;
  memset(&gctx, 0, sizeof(gctx));
  gctx.psbt = psbt;
  if (!psbt_read_map(&r, psbt_global_cb, &gctx)) PSBT_FAIL(3);

  // Determine version. Explicit 0xfb wins; otherwise infer from structure
  // (unsigned-tx present ⇒ v0; v2 globals present ⇒ v2).
  uint8_t ver;
  if (gctx.has_version) {
    ver = (uint8_t)gctx.version;
  } else if (gctx.has_unsigned_tx) {
    ver = 0;
  } else if (gctx.has_v2_tx_version) {
    ver = 2;
  } else {
    PSBT_FAIL(4);  // neither v0 nor v2 markers — malformed
  }
  psbt->psbt_version = ver;

  if (ver == 0) {
    // ── PSBTv0: parse the embedded unsigned tx for counts + tx fields ──
    if (!gctx.has_unsigned_tx) PSBT_FAIL(5);
    if (!psbt_parse_unsigned_tx(gctx.unsigned_tx_buf, gctx.unsigned_tx_len, &psbt->tx)) {
      PSBT_FAIL(6);
    }
    // Per-input maps (exactly n_inputs of them)
    for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
      psbt_input_ctx_t ictx = { &psbt->inputs[i], &psbt->tx.inputs[i], false };
      if (!psbt_read_map(&r, psbt_input_cb, &ictx)) PSBT_FAIL(7);
    }
    // Per-output maps (exactly n_outputs of them)
    for (uint8_t i = 0; i < psbt->tx.n_outputs; i++) {
      psbt_output_ctx_t octx = { &psbt->outputs[i], &psbt->tx.outputs[i], false };
      if (!psbt_read_map(&r, psbt_output_cb, &octx)) PSBT_FAIL(8);
    }
  } else {
    // ── PSBTv2 (BIP-370): tx fields come from global + per-map keys ──
    if (gctx.has_unsigned_tx) PSBT_FAIL(9);            // forbidden in v2
    if (!gctx.has_v2_tx_version) PSBT_FAIL(10);
    if (!gctx.has_v2_in_count || !gctx.has_v2_out_count) PSBT_FAIL(11);
    if (gctx.v2_in_count == 0 || gctx.v2_in_count > PSBT_MAX_INPUTS) PSBT_FAIL(12);
    if (gctx.v2_out_count == 0 || gctx.v2_out_count > PSBT_MAX_OUTPUTS) PSBT_FAIL(13);

    psbt->tx.version  = gctx.v2_tx_version;
    psbt->tx.locktime = gctx.v2_locktime;   // 0 if absent — acceptable default
    psbt->tx.n_inputs  = (uint8_t)gctx.v2_in_count;
    psbt->tx.n_outputs = (uint8_t)gctx.v2_out_count;

    // Per-input maps. Default sequence to 0xffffffff (absent 0x10 means final).
    for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
      psbt->tx.inputs[i].n_sequence = 0xffffffffUL;
      psbt_input_ctx_t ictx = { &psbt->inputs[i], &psbt->tx.inputs[i], true };
      if (!psbt_read_map(&r, psbt_input_cb, &ictx)) PSBT_FAIL(14);
    }
    // Per-output maps — amount + script are mandatory in v2.
    for (uint8_t i = 0; i < psbt->tx.n_outputs; i++) {
      psbt->tx.outputs[i].script_pubkey_len = 0;
      psbt_output_ctx_t octx = { &psbt->outputs[i], &psbt->tx.outputs[i], true };
      if (!psbt_read_map(&r, psbt_output_cb, &octx)) PSBT_FAIL(15);
      if (psbt->tx.outputs[i].script_pubkey_len == 0) PSBT_FAIL(16);  // script required
    }
  }

  // No trailing bytes allowed
  if (r.pos != r.len) PSBT_FAIL(17);
  // 23 Nov 2026 (#57): prove each input's amount from its previous transaction.
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
    psbt_input_t *in = &psbt->inputs[i];
    if (!in->nwu_ptr) continue;
    const uint8_t *p = in->nwu_ptr; uint32_t pl = in->nwu_len;
    in->nwu_ptr = NULL; in->nwu_len = 0;
    uint64_t v = 0; uint8_t spk[PSBT_MAX_SCRIPT_LEN]; uint8_t sl = 0;
    if (!psbt_prev_tx_check(p, pl, psbt->tx.inputs[i].prev_txid, psbt->tx.inputs[i].prev_vout, &v, spk, &sl)) PSBT_FAIL(19);
    if (in->witness_utxo_present) {
      if (in->witness_utxo_value != v || in->witness_utxo_script_len != sl ||
          memcmp(in->witness_utxo_script, spk, sl) != 0) PSBT_FAIL(20);
    } else {
      in->witness_utxo_value = v; memcpy(in->witness_utxo_script, spk, sl);
      in->witness_utxo_script_len = sl; in->witness_utxo_present = true;
    }
    in->nwu_verified = true;
  }
  // 11bl (issue #47 item 8): no amount above the 21 million BTC cap. Such a
  // transaction is invalid on chain anyway, and refusing it here keeps every
  // review sum (at most PSBT_MAX_INPUTS + PSBT_MAX_OUTPUTS such values) far
  // from 64-bit wrap, so the fee shown is always the real one.
  for (uint8_t i = 0; i < psbt->tx.n_outputs; i++)
    if (psbt->tx.outputs[i].value > PSBT_MAX_MONEY) PSBT_FAIL(18);
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++)
    if (psbt->inputs[i].witness_utxo_present && psbt->inputs[i].witness_utxo_value > PSBT_MAX_MONEY) PSBT_FAIL(18);
  return true;
}
