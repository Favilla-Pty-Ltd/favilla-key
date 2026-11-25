#pragma once
// ============================================================
// psbt_sign.h — PSBT signing orchestration.
//
// Takes a parsed PSBT (psbt.h), verifies each input that claims to be
// ours, computes the BIP-143 sighash (bip143.h), signs with ECDSA
// (secp256k1_ecdsa.h), and emits a compact array of partial signatures
// for the PWA to combine with the original PSBT.
//
// Verification before signing — this is the entire reason a hardware
// wallet exists. For each input that claims to be ours (via BIP32
// fingerprint match), we re-derive the pubkey from our seed at the
// claimed path and verify:
//   1. Derived pubkey == pubkey in PSBT_IN_BIP32_DERIVATION
//   2. HASH160(pubkey) == 20-byte pkh inside the witness UTXO script
//      (P2WPKH scriptPubKey is 0x0014 || <20-byte pkh>)
//
// Both checks must pass or we refuse to sign. This is what prevents
// a malicious PWA from tricking the device into signing inputs that
// aren't actually ours.
//
// Approval: this module does not display anything. It exposes a
// summary struct (psbt_summary_t) with the data needed for the
// trusted display, plus a separate `sign` step that's gated by a
// caller-supplied `approved` boolean. The on-screen UI is wired in
// the API handler.
// ============================================================

#include "psbt.h"
#include "bip143.h"
#include "secp256k1_ecdsa.h"
#include "bip84.h"
#include "hash160.h"

// PSBTDIAG logging. This header is included from main.cpp (via ur_psbt.h)
// long before the LOG_* macros are defined, so it needs its own. Arduino.h
// precedes it, so Serial is available. Remove with the diagnostics.
#ifndef PSBTDIAG
  #define PSBTDIAG(...) Serial.printf(__VA_ARGS__)
#endif

#define PSBT_MAX_SIGNABLE_INPUTS PSBT_MAX_INPUTS

// One per signable input, output of the orchestration.
typedef struct {
  uint8_t input_index;          // which tx input this is
  uint8_t pubkey[33];           // compressed pubkey that signed
  uint8_t der[80];              // DER signature
  uint8_t der_len;
  uint8_t sighash_type;         // appended after DER in scriptSig/witness
} psbt_partial_sig_t;

// Summary of the transaction, for on-screen confirmation. The
// classification here is what gets displayed — the device draws its
// truth from the PSBT contents, never from any PWA-supplied label.
typedef struct {
  // Recipients (non-change outputs)
  struct {
    uint8_t  script_pubkey[PSBT_MAX_SCRIPT_LEN];
    uint8_t  script_pubkey_len;
    uint64_t value;
  } recipients[PSBT_MAX_OUTPUTS];
  uint8_t n_recipients;

  // Change outputs. An output is *claimed* change if its BIP32 metadata
  // carries our fingerprint — but a fingerprint is a public, spoofable hint,
  // so each is independently VERIFIED by re-deriving the address from our
  // seed at the claimed path and confirming it matches the output script
  // (see psbt_verify_change_output). `verified` is true only when that proof
  // passes. An unverified "change" output is a possible change-redirection
  // attack and must be surfaced to the user, never shown as safe.
  struct {
    uint8_t  script_pubkey[PSBT_MAX_SCRIPT_LEN];
    uint8_t  script_pubkey_len;
    uint64_t value;
    bool     verified;          // true = re-derived from our seed and matches
  } changes[PSBT_MAX_OUTPUTS];
  uint8_t n_changes;
  uint8_t n_changes_unverified; // count of changes that failed verification

  uint64_t total_in;             // sum of all our input amounts
  uint64_t total_recipients;     // sum of non-change output values
  uint64_t total_change;         // sum of change output values
  uint64_t fee;                  // total_in - (total_recipients + total_change)
} psbt_summary_t;

// Forward decls for the helpers below
static bool psbt_verify_input_ownership(const psbt_input_t *in,
                                         const psbt_txin_t *txin,
                                         const uint8_t seed[64],
                                         const uint8_t our_fp[4],
                                         uint32_t *change_out,
                                         uint32_t *index_out);

// Maximum address index we'll accept as legitimate change. A change output
// claiming an index far beyond what a normal wallet has issued is a red flag:
// the address may verify as "ours" cryptographically yet sit on a path you'll
// never scan or recover, effectively stranding the funds. 1000 is generous
// for a personal wallet while still rejecting absurd indices.
#ifndef PSBT_CHANGE_GAP_LIMIT
#define PSBT_CHANGE_GAP_LIMIT 1000
#endif

// Pubkey-derivation callback. Given a BIP-84 (change, index) leaf, write the
// 33-byte compressed pubkey and return true. This decouples verification from
// HOW the key is derived: the caller supplies a seed-free CKD-pub derivation
// (from the cached account xpub) so change verification never touches the seed
// or a spend session. The two-door watch-only path depends on this.
typedef bool (*psbt_derive_pubkey_fn)(uint32_t change, uint32_t index,
                                       uint8_t pub33_out[33]);

// v3 (16 Sep 2026): the private key never exists on this processor. Signing
// is a callback into the G0 (g0_btc_sign via bitcoin_menu.inc). req is the
// 416-byte fixed request (g0_btc_build_request). The callee returns the
// pubkey IT derived, the DER signature and the sighash IT signed; the callers
// below compare both against their own values and refuse on mismatch.
typedef bool (*psbt_g0_sign_fn)(const uint8_t req[416], uint8_t pub33_out[33],
                                uint8_t der_out[72], uint8_t* der_len_out,
                                uint8_t sighash_out[32]);
// Request builder, defined in g0_signer.cpp (prototype repeated here so this
// header stays buildable in the host harness without Arduino/Wire; the
// harness supplies its own definition).
bool g0_btc_build_request(uint8_t req[416], uint8_t kind,
                          uint32_t version, uint32_t locktime,
                          const uint8_t hashPrevouts[32], const uint8_t hashSequence[32],
                          const uint8_t hashOutputs[32], const uint8_t outpoint[36],
                          uint32_t nSequence, uint64_t amount,
                          uint32_t change, uint32_t index,
                          const uint8_t* witness_script, size_t witness_script_len);

// ── Change output verification (SEED-FREE) ───────────────────────────────
//
// Proves an output genuinely belongs to our wallet as change, with the SAME
// rigor as input ownership verification. A fingerprint match alone is
// insufficient — the 4-byte fingerprint is public and an attacker can attach
// it to an output paying THEIR address (the "change redirection" attack). We
// defend by re-deriving the address ourselves (via the supplied derive_pub
// callback, which uses the account XPUB — no seed) and matching it.
//
// All checks must pass:
//   (a) BIP32 metadata present and fingerprint matches ours
//   (b) Path is exactly m/84'/0'/0'/{change}/{index}, change in {0,1},
//       index unhardened and within the gap limit
//   (c) Re-derive the pubkey at that path from the account xpub (CKD-pub)
//   (d) Re-derived pubkey matches the output's claimed BIP32 pubkey
//   (e) HASH160(pubkey) matches the output's actual P2WPKH scriptPubKey
//
// Returns true only if this output is provably our change. derive_pub must be
// non-NULL; a NULL callback (or a derivation failure) yields false — an output
// we cannot prove is ours is treated as unverified, never as safe change.
static bool psbt_verify_change_output(const psbt_output_t *o,
                                       const psbt_txout_t *txout,
                                       psbt_derive_pubkey_fn derive_pub,
                                       const uint8_t our_fp[4]) {
  if (!derive_pub) return false;

  // (a) fingerprint
  if (!o->bip32.present) return false;
  if (memcmp(o->bip32.fingerprint, our_fp, 4) != 0) return false;

  // (b) BIP-84 path shape: m/84'/0'/0'/c/i
  if (o->bip32.path_len != 5) return false;
  if (o->bip32.path[0] != (0x80000000U | 84U)) return false;
  if (o->bip32.path[1] != (0x80000000U | 0U))  return false;
  if (o->bip32.path[2] != (0x80000000U | 0U))  return false;
  uint32_t change = o->bip32.path[3];
  uint32_t index  = o->bip32.path[4];
  if (change > 1) return false;              // external or change chain only
  if (index & 0x80000000U) return false;     // unhardened leaves only
  if (index > PSBT_CHANGE_GAP_LIMIT) return false;  // not absurdly far out

  // (c) re-derive pubkey at the claimed path from the account xpub (no seed)
  uint8_t derived_pubkey[33];
  if (!derive_pub(change, index, derived_pubkey)) return false;

  // (d) re-derived pubkey must match the output's claimed pubkey
  if (memcmp(derived_pubkey, o->bip32.pubkey, 33) != 0) return false;

  // (e) the OUTPUT's actual scriptPubKey must be P2WPKH(HASH160(pubkey)):
  //     0x00 0x14 <20-byte pkh>. This defeats redirection — the script the
  //     coins actually go to must match our derived address.
  if (txout->script_pubkey_len != 22) return false;
  if (txout->script_pubkey[0] != 0x00) return false;
  if (txout->script_pubkey[1] != 0x14) return false;
  uint8_t pkh[20];
  hash160(derived_pubkey, 33, pkh);
  if (memcmp(txout->script_pubkey + 2, pkh, 20) != 0) return false;

  return true;   // provably our change
}

// ── Build summary ────────────────────────────────────────────────────
//
// Classifies each tx output as recipient or change based on whether
// its PSBT output map has BIP32 metadata matching our fingerprint.
// Sums input amounts from each input's witness UTXO. Computes fee.
//
// Returns false if any input lacks witness UTXO data (we can't compute
// fee without knowing what each input is worth). The PWA must populate
// witness UTXO for every input it expects us to consider, including
// inputs that aren't ours (for fee calculation).
static bool psbt_build_summary(const psbt_t *psbt, const uint8_t our_fp[4],
                                psbt_derive_pubkey_fn derive_pub,
                                psbt_summary_t *sum) {
  memset(sum, 0, sizeof(*sum));

  // Sum input amounts. We require witness_utxo on every input so we can
  // compute the fee — without it, the device cannot trust the fee value.
  // BIP-143 signatures already commit to the input amount, so the PWA
  // has every incentive to provide accurate witness UTXOs.
  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
    if (!psbt->inputs[i].witness_utxo_present) return false;
    sum->total_in += psbt->inputs[i].witness_utxo_value;
  }

  // Classify each output. An output is "change" ONLY if it cryptographically
  // verifies as ours (re-derived address matches). An output whose fingerprint
  // matches but which fails verification is recorded as change-but-UNVERIFIED:
  // NOT counted as a recipient (so we don't hide it) and NOT presented as safe
  // change (its `verified` flag is false). This is the redirection defense.
  for (uint8_t i = 0; i < psbt->tx.n_outputs; i++) {
    const psbt_txout_t *out = &psbt->tx.outputs[i];
    bool claims_change = psbt->outputs[i].bip32.present &&
                         memcmp(psbt->outputs[i].bip32.fingerprint, our_fp, 4) == 0;

    if (claims_change) {
      bool ok = psbt_verify_change_output(&psbt->outputs[i], out, derive_pub, our_fp);
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

  // Fee = input total - output total. If outputs exceed inputs the PSBT
  // is malformed (caller should reject).
  uint64_t total_out = sum->total_recipients + sum->total_change;
  if (total_out > sum->total_in) return false;
  sum->fee = sum->total_in - total_out;
  return true;
}

// ── Input ownership verification ─────────────────────────────────────
//
// Returns true iff this input is provably ours and safe to sign.
// On success, returns the (change, index) path components so the
// caller can use them directly with bip84_derive_address_privkey.
//
// Verification steps:
//   (a) BIP32 fingerprint matches our master fingerprint
//   (b) BIP32 path is exactly m/84'/0'/0'/{change}/{index} where
//       change ∈ {0, 1} (external or change chain). Tightening
//       to BIP-84 standard prevents accidental signing of paths
//       outside the wallet's address space.
//   (c) Re-derive the privkey at that path; compute compressed pubkey;
//       verify it matches the PSBT's claimed pubkey
//   (d) Verify the witness UTXO's scriptPubKey is P2WPKH(HASH160(pubkey))
//   (e) Verify the input's sighash type (if specified) is SIGHASH_ALL
//
// All five checks pass → this is genuinely our input.
//
// We don't need txin in this function but keep the param for caller
// clarity (it's the tx-level input that this PSBT input corresponds to;
// future checks might cross-reference).
static bool psbt_verify_input_ownership(const psbt_input_t *in,
                                         const psbt_txin_t *txin,
                                         const uint8_t seed[64],
                                         const uint8_t our_fp[4],
                                         uint32_t *change_out,
                                         uint32_t *index_out) {
  (void)txin;
  if (!in->bip32.present) return false;
  if (!in->witness_utxo_present) return false;

  // (a) fingerprint
  if (memcmp(in->bip32.fingerprint, our_fp, 4) != 0) return false;

  // (b) BIP-84 path shape: m/84'/0'/0'/c/i
  if (in->bip32.path_len != 5) return false;
  if (in->bip32.path[0] != (0x80000000U | 84U)) return false;
  if (in->bip32.path[1] != (0x80000000U | 0U))  return false;
  if (in->bip32.path[2] != (0x80000000U | 0U))  return false;
  uint32_t change = in->bip32.path[3];
  uint32_t index  = in->bip32.path[4];
  if (change > 1) return false;            // external or change chain only
  if (index & 0x80000000U) return false;   // unhardened leaves only

  // (e) sighash type — only SIGHASH_ALL (or absent=0, which we treat as ALL)
  if (in->sighash_type != 0 && in->sighash_type != 0x01) return false;

  // (c) re-derive privkey, compute pubkey, compare to PSBT-claimed pubkey
  uint8_t priv[32];
  if (!bip84_derive_address_privkey(seed, BIP84_NETWORK_MAINNET,
                                     change, index, priv)) {
    return false;
  }
  // Compressed pubkey from priv. We don't have a "pub from priv" helper
  // in secp256k1.h directly, but pt_mul_base does k*G — same operation.
  sc d;  sc_from_b32(&d, priv);  sc_reduce_once(&d);
  memset(priv, 0, 32);
  JPt P_j;  pt_mul_base(&P_j, &d);
  Pt P;     jpt_to_affine(&P, &P_j);
  fe_norm(&P.x);  fe_norm(&P.y);
  uint8_t derived_pubkey[33];
  derived_pubkey[0] = fe_is_odd(&P.y) ? 0x03 : 0x02;
  fe_to_b32(derived_pubkey + 1, &P.x);

  if (memcmp(derived_pubkey, in->bip32.pubkey, 33) != 0) return false;

  // (d) witness UTXO scriptPubKey must be P2WPKH(HASH160(pubkey)):
  //     0x00 0x14 <20-byte pkh>
  if (in->witness_utxo_script_len != 22) return false;
  if (in->witness_utxo_script[0] != 0x00) return false;
  if (in->witness_utxo_script[1] != 0x14) return false;
  uint8_t pkh[20];
  hash160(derived_pubkey, 33, pkh);
  if (memcmp(in->witness_utxo_script + 2, pkh, 20) != 0) return false;

  *change_out = change;
  *index_out  = index;
  return true;
}

// ── Input ownership verification (SEED-FREE, for preview/count) ──────────
//
// Same checks as psbt_verify_input_ownership, but derives the pubkey from the
// account xpub via the supplied callback instead of from the seed. Used during
// the PSBT preview to count signable inputs and to drive the display, all on a
// daily-door unlock with no seed resident. The actual signing step (Task 3)
// still uses the seed-based variant inside a spend session — this function
// only proves "this input is ours", it does not and cannot sign.
//
// Returns true and fills (change_out, index_out) iff the input is provably
// ours. derive_pub must be non-NULL.
static bool psbt_verify_input_ownership_pub(const psbt_input_t *in,
                                             const psbt_txin_t *txin,
                                             psbt_derive_pubkey_fn derive_pub,
                                             const uint8_t our_fp[4],
                                             uint32_t *change_out,
                                             uint32_t *index_out) {
  (void)txin;
  // PSBTDIAG: report WHICH gate rejected the input. "No inputs match this
  // wallet" is unactionable when key, paths and addresses all agree across
  // wallets — the cause is usually an ENCODING difference. Remove once fixed.
  if (!derive_pub) { PSBTDIAG("[PSBTDIAG] no derive_pub\n"); return false; }
  if (!in->bip32.present) { PSBTDIAG("[PSBTDIAG] no BIP32 derivation on input\n"); return false; }
  if (!in->witness_utxo_present) {
    PSBTDIAG("[PSBTDIAG] NO witness UTXO on input (legacy/non-witness UTXO?)\n");
    return false;
  }

  // (a) fingerprint
  if (memcmp(in->bip32.fingerprint, our_fp, 4) != 0) {
    PSBTDIAG("[PSBTDIAG] fp mismatch: psbt %02x%02x%02x%02x vs ours %02x%02x%02x%02x\n",
             in->bip32.fingerprint[0], in->bip32.fingerprint[1],
             in->bip32.fingerprint[2], in->bip32.fingerprint[3],
             our_fp[0], our_fp[1], our_fp[2], our_fp[3]);
    return false;
  }

  // (b) BIP-84 path shape: m/84'/0'/0'/c/i
  if (in->bip32.path_len != 5) {
    PSBTDIAG("[PSBTDIAG] path_len %u (expect 5)\n", (unsigned)in->bip32.path_len);
    return false;
  }
  if (in->bip32.path[0] != (0x80000000U | 84U) ||
      in->bip32.path[1] != (0x80000000U | 0U)  ||
      in->bip32.path[2] != (0x80000000U | 0U)) {
    PSBTDIAG("[PSBTDIAG] path prefix %08lx/%08lx/%08lx (expect 80000054/80000000/80000000)\n",
             (unsigned long)in->bip32.path[0], (unsigned long)in->bip32.path[1],
             (unsigned long)in->bip32.path[2]);
    return false;
  }
  uint32_t change = in->bip32.path[3];
  uint32_t index  = in->bip32.path[4];
  if (change > 1) return false;            // external or change chain only
  if (index & 0x80000000U) return false;   // unhardened leaves only

  // (e) sighash type — only SIGHASH_ALL (or absent=0, which we treat as ALL)
  if (in->sighash_type != 0 && in->sighash_type != 0x01) {
    PSBTDIAG("[PSBTDIAG] sighash type 0x%02x (only SIGHASH_ALL accepted)\n",
             (unsigned)in->sighash_type);
    return false;
  }

  // (c) re-derive pubkey from the account xpub (no seed), compare to claimed
  uint8_t derived_pubkey[33];
  if (!derive_pub(change, index, derived_pubkey)) {
    PSBTDIAG("[PSBTDIAG] derive_pub failed for %lu/%lu\n",(unsigned long)change,(unsigned long)index);
    return false;
  }
  if (memcmp(derived_pubkey, in->bip32.pubkey, 33) != 0) {
    PSBTDIAG("[PSBTDIAG] pubkey mismatch at %lu/%lu\n",(unsigned long)change,(unsigned long)index);
    return false;
  }

  // (d) witness UTXO scriptPubKey must be P2WPKH(HASH160(pubkey)):
  //     0x00 0x14 <20-byte pkh>
  if (in->witness_utxo_script_len != 22 ||
      in->witness_utxo_script[0] != 0x00 || in->witness_utxo_script[1] != 0x14) {
    PSBTDIAG("[PSBTDIAG] scriptPubKey not P2WPKH (len %u)\n",
             (unsigned)in->witness_utxo_script_len);
    return false;
  }
  uint8_t pkh[20];
  hash160(derived_pubkey, 33, pkh);
  if (memcmp(in->witness_utxo_script + 2, pkh, 20) != 0) {
    PSBTDIAG("[PSBTDIAG] scriptPubKey hash160 mismatch (address is not ours)\n");
    return false;
  }

  *change_out = change;
  *index_out  = index;
  return true;
}
//   - hands a fixed-length request to the G0 (v3: the seed and every private
//     key live ONLY on the G0), cross-checks its pubkey and sighash
//   - Appends to sigs_out[]
// Returns the number of signatures produced, or -1 on any error.
//
// Caller must have already obtained user approval (this function does
// not display anything). Passing `approved=false` is a hard refusal:
// the function returns 0 without computing any sighash or touching
// keys. This makes it impossible to accidentally sign without explicit
// approval upstream.
//
// v3: no seed, no private key on this processor at any point.
static int psbt_sign_all(const psbt_t *psbt, psbt_g0_sign_fn g0_sign,
                          psbt_derive_pubkey_fn derive_pub,
                          const uint8_t our_fp[4], bool approved,
                          psbt_partial_sig_t *sigs_out, int sigs_cap) {
  if (!approved) return 0;
  if (sigs_cap < 1 || !g0_sign || !derive_pub) return -1;

  // Build the three pre-hashes once and reuse for every input
  // (BIP-143 § hashPrevouts/hashSequence/hashOutputs).
  bip143_input_t bin[PSBT_MAX_INPUTS];
  bip143_output_t bout[PSBT_MAX_OUTPUTS];
  memset(bin, 0, sizeof(bin));
  memset(bout, 0, sizeof(bout));

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
    bout[i].value = o->value;
    if ((size_t)o->script_pubkey_len + 1 > sizeof(bout[i].scriptPubKey)) return 0;
    bout[i].scriptPubKey[0] = o->script_pubkey_len;
    memcpy(bout[i].scriptPubKey + 1, o->script_pubkey, o->script_pubkey_len);
    bout[i].scriptPubKey_len = o->script_pubkey_len + 1;
  }

  uint8_t hashPrevouts[32], hashSequence[32], hashOutputs[32];
  bip143_tx_hashes(bin, psbt->tx.n_inputs, bout, psbt->tx.n_outputs,
                   hashPrevouts, hashSequence, hashOutputs);

  int n_sigs = 0;

  for (uint8_t i = 0; i < psbt->tx.n_inputs; i++) {
    uint32_t change, index;
    // Seed-free ownership proof from the account xpub the G0 handed over at
    // door entry (fingerprint, path shape, pubkey, P2WPKH hash160).
    if (!psbt_verify_input_ownership_pub(&psbt->inputs[i], &psbt->tx.inputs[i],
                                          derive_pub, our_fp, &change, &index)) {
      continue;   // not ours — other signers handle their own inputs
    }
    if (n_sigs >= sigs_cap) return -1;

    // Our own BIP-143 sighash for this input, computed exactly as before.
    bip143_input_t *bi = &bin[i];
    bi->amount = psbt->inputs[i].witness_utxo_value;
    bi->scriptCode_len = bip143_p2wpkh_scriptcode(
      psbt->inputs[i].witness_utxo_script + 2, bi->scriptCode);
    uint8_t sighash[32];
    bip143_input_sighash(psbt->tx.version, psbt->tx.locktime, bi,
                         hashPrevouts, hashSequence, hashOutputs,
                         BIP143_SIGHASH_ALL, sighash);

    // Fixed-length request to the G0. It derives m/84'/0'/0'/change/index
    // itself, rebuilds the scriptCode from ITS pubkey, recomputes the sighash
    // and signs. We accept the answer only if its pubkey is the one the PSBT
    // (and our xpub) say, and its sighash is the one we just computed.
    uint8_t req[416];
    if (!g0_btc_build_request(req, 1, psbt->tx.version, psbt->tx.locktime,
                              hashPrevouts, hashSequence, hashOutputs, bi->outpoint,
                              bi->nSequence, bi->amount, change, index, nullptr, 0)) return -1;
    uint8_t pub[33], der[72], dl = 0, sh[32];
    bool ok = g0_sign(req, pub, der, &dl, sh);
    memset(req, 0, sizeof(req));
    if (!ok) return -1;
    if (memcmp(pub, psbt->inputs[i].bip32.pubkey, 33) != 0) {
      PSBTDIAG("[psbt] G0 derived a different pubkey for %lu/%lu - refusing its signature\n", (unsigned long)change, (unsigned long)index);
      return -1;
    }
    if (memcmp(sh, sighash, 32) != 0) {
      PSBTDIAG("[psbt] G0 sighash != ESP32 sighash for input %u - refusing (bip143 mismatch)\n", i);
      return -1;
    }

    psbt_partial_sig_t *out = &sigs_out[n_sigs++];
    out->input_index = i;
    memcpy(out->pubkey, pub, 33);
    memcpy(out->der, der, dl);
    out->der_len = dl;
    out->sighash_type = BIP143_SIGHASH_ALL;
  }

  return n_sigs;
}
