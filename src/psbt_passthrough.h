#pragma once
// ============================================================================
// psbt_passthrough.h — return a PSBT with our PSBT_IN_PARTIAL_SIG entries
//                      added and EVERYTHING ELSE copied byte-for-byte.
//
// A cosigner cannot finalise: the other signers still need the witness UTXO,
// the witness script, every derivation record and any partial sigs already
// present. BIP-174 requires a signer to pass unknown keys through, and the
// parser in psbt.h is deliberately lossy — so we do not re-serialise from the
// struct. We walk the ORIGINAL bytes map by map, copy every keypair verbatim,
// and splice our 0x02 entries into the input maps they belong to.
//
// Also used for the single-sig case where a PSBT carries a foreign input: the
// old ur_build_finalized_psbt() refused those ("Foreign input — can't
// finalize"). Returning partial sigs lets the coordinator finalise instead.
//
// Rules:
//   - The unsigned tx / global map / output maps are copied untouched.
//   - In each input map, an existing 0x02 entry with the SAME pubkey as one we
//     are adding is dropped and replaced (re-signing is idempotent). Other
//     cosigners' partial sigs are preserved.
//   - Map order and key order are preserved. Our entries go at the END of
//     the input map, before its 0x00 separator.
//   - Any structural surprise (short read, oversized key/value, wrong map
//     count) fails the whole write. Never emit a partial result.
// ============================================================================

#include <stdint.h>
#include <string.h>
#include "psbt.h"
#include "psbt_sign.h"

// Write a compact-size varint. Returns bytes written.
static size_t pp_write_varint(uint8_t *o, uint64_t v) {
  if (v < 0xFD)        { o[0] = (uint8_t)v; return 1; }
  if (v <= 0xFFFF)     { o[0] = 0xFD; o[1] = v & 0xFF; o[2] = (v >> 8) & 0xFF; return 3; }
  if (v <= 0xFFFFFFFF) { o[0] = 0xFE; for (int i = 0; i < 4; i++) o[1 + i] = (v >> (8 * i)) & 0xFF; return 5; }
  o[0] = 0xFF; for (int i = 0; i < 8; i++) o[1 + i] = (v >> (8 * i)) & 0xFF; return 9;
}

typedef struct { uint8_t *out; size_t cap; size_t pos; bool ok; } pp_writer_t;
static void pp_put(pp_writer_t *w, const uint8_t *b, size_t n) {
  if (!w->ok) return;
  if (w->pos + n > w->cap) { w->ok = false; return; }
  memcpy(w->out + w->pos, b, n); w->pos += n;
}
static void pp_put_varint(pp_writer_t *w, uint64_t v) { uint8_t t[9]; size_t n = pp_write_varint(t, v); pp_put(w, t, n); }

// Copy one map from r to w. `input_index` >= 0 means this is an input map and
// our sigs for that input are appended. Returns false on malformed input.
static bool pp_copy_map(psbt_reader_t *r, pp_writer_t *w, int input_index,
                        const psbt_partial_sig_t *sigs, int n_sigs) {
  for (;;) {
    uint64_t keylen;
    if (!psbt_r_varint(r, &keylen)) return false;
    if (keylen == 0) break;                       // separator
    if (keylen > 128) return false;
    const uint8_t *key = psbt_r_view(r, keylen);
    if (!key) return false;
    uint64_t vallen;
    if (!psbt_r_varint(r, &vallen)) return false;
    if (vallen > 4096) return false;
    const uint8_t *val = psbt_r_view(r, vallen);
    if (!val) return false;

    // Drop an existing partial sig for a pubkey we are about to write.
    if (input_index >= 0 && key[0] == 0x02 && keylen == 34) {
      bool ours = false;
      for (int j = 0; j < n_sigs; j++)
        if (sigs[j].input_index == input_index && memcmp(sigs[j].pubkey, key + 1, 33) == 0) { ours = true; break; }
      if (ours) continue;
    }
    pp_put_varint(w, keylen); pp_put(w, key, keylen);
    pp_put_varint(w, vallen); pp_put(w, val, vallen);
  }
  if (input_index >= 0) {
    for (int j = 0; j < n_sigs; j++) {
      if (sigs[j].input_index != input_index) continue;
      uint8_t key[34]; key[0] = 0x02; memcpy(key + 1, sigs[j].pubkey, 33);
      pp_put_varint(w, 34); pp_put(w, key, 34);
      pp_put_varint(w, (uint64_t)sigs[j].der_len + 1);
      pp_put(w, sigs[j].der, sigs[j].der_len);
      uint8_t sh = sigs[j].sighash_type; pp_put(w, &sh, 1);
    }
  }
  uint8_t sep = 0x00; pp_put(w, &sep, 1);
  return w->ok;
}

// in/in_len: the ORIGINAL PSBT bytes as scanned. parsed: the psbt_t from
// psbt_parse(in) (only n_inputs/n_outputs are used). Returns bytes written to
// out, or -1.
static int psbt_add_partial_sigs(const uint8_t *in, size_t in_len, const psbt_t *parsed,
                                 const psbt_partial_sig_t *sigs, int n_sigs,
                                 uint8_t *out, size_t out_cap) {
  if (!in || !parsed || !out || in_len < 5 || n_sigs < 0) return -1;
  for (int j = 0; j < n_sigs; j++)
    if (sigs[j].input_index >= parsed->tx.n_inputs || sigs[j].der_len == 0 || sigs[j].der_len > 80) return -1;
  psbt_reader_t r = { in, in_len, 0 };
  pp_writer_t w = { out, out_cap, 0, true };
  static const uint8_t MAGIC[5] = { 0x70, 0x73, 0x62, 0x74, 0xff };
  const uint8_t *m = psbt_r_view(&r, 5);
  if (!m || memcmp(m, MAGIC, 5) != 0) return -1;
  pp_put(&w, MAGIC, 5);
  if (!pp_copy_map(&r, &w, -1, NULL, 0)) return -1;                       // global
  for (uint8_t i = 0; i < parsed->tx.n_inputs; i++)
    if (!pp_copy_map(&r, &w, (int)i, sigs, n_sigs)) return -1;           // inputs
  for (uint8_t i = 0; i < parsed->tx.n_outputs; i++)
    if (!pp_copy_map(&r, &w, -1, NULL, 0)) return -1;                     // outputs
  if (r.pos != r.len) return -1;                                          // trailing bytes
  return w.ok ? (int)w.pos : -1;
}
