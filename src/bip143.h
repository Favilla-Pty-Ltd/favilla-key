#pragma once
// ============================================================
// bip143.h — BIP-143 sighash for segwit v0 P2WPKH inputs.
//
// The sighash is the message that gets ECDSA-signed for a segwit input.
// Computed as double-SHA256 of a precise serialization defined by
// BIP-143, which fixes weaknesses in the legacy sighash algorithm.
//
// Validated against the BIP-143 published test vector:
//   priv  = 619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
//   pkh   = 1d0f172a0ecb48aee1be1f2687d2963ae33f71a1
//   amount= 600000000 (6 BTC)
//   ...
//   sighash = c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670
//
// Caller responsibilities:
//   - Provide the witness UTXO data for the input being signed
//     (script + amount). BIP-84 P2WPKH is the only scriptPubKey we
//     support; the scriptCode is templated as
//     0x1976a914{20-byte-pubkey-hash}88ac.
//   - hashPrevouts, hashSequence, hashOutputs may be reused across
//     multiple inputs in the same tx. The bip143_tx_hashes() helper
//     computes all three at once; bip143_input_sighash() builds the
//     final preimage and double-SHAs it.
// ============================================================

#include <stdint.h>
#include <string.h>
#include <mbedtls/sha256.h>

// V-1 fix: scripts are varint-prefixed, so the field/buffers must hold the
// parser's max script length PLUS the 1-byte varint. Sized from psbt.h's cap.
#ifndef PSBT_MAX_SCRIPT_LEN
#define PSBT_MAX_SCRIPT_LEN 40
#endif
#ifndef PSBT_MAX_OUTPUTS
#define PSBT_MAX_OUTPUTS 8
#endif
#define BIP143_MAX_SCRIPT (PSBT_MAX_SCRIPT_LEN + 1)
// Multisig (14 Sep 2026): a P2WSH scriptCode is varint || witnessScript, so it
// can be up to PSBT_MAX_WITNESS_SCRIPT + 3 bytes. bip143_input_t keeps its
// small scriptCode buffer for P2WPKH; P2WSH callers hand the scriptCode in by
// pointer via bip143_input_sighash_sc() and the preimage buffer is sized for it.
#ifndef PSBT_MAX_WITNESS_SCRIPT
#define PSBT_MAX_WITNESS_SCRIPT 256
#endif
#define BIP143_MAX_SCRIPTCODE (PSBT_MAX_WITNESS_SCRIPT + 3)
#define BIP143_PREIMAGE_CAP   (4 + 32 + 32 + 36 + BIP143_MAX_SCRIPTCODE + 8 + 4 + 32 + 4 + 4)

#define BIP143_SIGHASH_ALL          0x01
#define BIP143_SIGHASH_NONE         0x02
#define BIP143_SIGHASH_SINGLE       0x03
#define BIP143_SIGHASH_ANYONECANPAY 0x80

// ── Double-SHA256 ──────────────────────────────────────────────────────
// dSHA256(x) = SHA256(SHA256(x)). Used everywhere in Bitcoin signing.
static void bip143_dsha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint8_t once[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, once);
    mbedtls_sha256_free(&ctx);
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, once, 32);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

// ── Input representation ───────────────────────────────────────────────
//
// One entry per input in the transaction. For the input we're signing,
// `amount` and `scriptCode_len`/`scriptCode` must be populated with the
// witness UTXO's amount and the P2WPKH scriptCode template (see header
// comment). For other inputs we only need outpoint + nSequence — they
// contribute to hashPrevouts and hashSequence but not to the sighash
// scriptCode/amount fields.
typedef struct {
    uint8_t  outpoint[36];   // 32-byte prev txid (LE) + 4-byte vout (LE)
    uint32_t nSequence;      // little-endian when serialised
    uint64_t amount;         // sats (only used for the input being signed)
    uint8_t  scriptCode[BIP143_MAX_SCRIPT]; // V-1: was [40]; +1 for varint
    size_t   scriptCode_len; // length of scriptCode bytes including varint
} bip143_input_t;

// One entry per output.
typedef struct {
    uint64_t value;            // sats
    uint8_t  scriptPubKey[BIP143_MAX_SCRIPT]; // V-1: was [40]; +1 for varint
    size_t   scriptPubKey_len; // length of scriptPubKey bytes including varint
} bip143_output_t;

// ── Pre-hash computation ───────────────────────────────────────────────
//
// All three pre-hashes can be computed once and reused across every
// input's sighash. This is the O(n^2) → O(n) optimisation BIP-143 was
// designed around.
//
// Assumes SIGHASH_ALL (no ANYONECANPAY/SINGLE/NONE flags). For these
// flags, hashPrevouts/hashSequence/hashOutputs are replaced with zeros
// per BIP-143 § "specification". We can add those code paths if/when a
// PSBT in the wild requests them; for now we just handle SIGHASH_ALL.
static void bip143_tx_hashes(const bip143_input_t *inputs, size_t n_in,
                             const bip143_output_t *outputs, size_t n_out,
                             uint8_t hashPrevouts[32],
                             uint8_t hashSequence[32],
                             uint8_t hashOutputs[32]) {
    // hashPrevouts: dSHA256 of all outpoints concatenated (36 bytes each)
    {
        size_t buflen = n_in * 36;
        uint8_t buf[36 * 8];  // up to 8 inputs; enlarge if needed
        for (size_t i = 0; i < n_in; i++) memcpy(buf + i * 36, inputs[i].outpoint, 36);
        bip143_dsha256(buf, buflen, hashPrevouts);
    }
    // hashSequence: dSHA256 of all nSequence values concatenated (4 bytes each LE)
    {
        size_t buflen = n_in * 4;
        uint8_t buf[4 * 8];
        for (size_t i = 0; i < n_in; i++) {
            uint32_t s = inputs[i].nSequence;
            buf[i*4+0] =  s        & 0xFF;
            buf[i*4+1] = (s >>  8) & 0xFF;
            buf[i*4+2] = (s >> 16) & 0xFF;
            buf[i*4+3] = (s >> 24) & 0xFF;
        }
        bip143_dsha256(buf, buflen, hashSequence);
    }
    // hashOutputs: dSHA256 of (8-byte value LE || scriptPubKey-with-varint) per output
    {
        uint8_t buf[(8 + BIP143_MAX_SCRIPT) * PSBT_MAX_OUTPUTS];  // V-1: was (8+40)*8=384; now 392
        size_t off = 0;
        for (size_t i = 0; i < n_out; i++) {
            uint64_t v = outputs[i].value;
            for (int b = 0; b < 8; b++) buf[off++] = (uint8_t)((v >> (8*b)) & 0xFF);
            memcpy(buf + off, outputs[i].scriptPubKey, outputs[i].scriptPubKey_len);
            off += outputs[i].scriptPubKey_len;
        }
        bip143_dsha256(buf, off, hashOutputs);
    }
}

// ── Per-input sighash ──────────────────────────────────────────────────
//
// Builds the BIP-143 preimage for one input and double-SHAs it.
// Inputs:
//   nVersion       — tx version (typically 1 or 2)
//   nLockTime      — tx locktime
//   input          — the input being signed (must have amount, scriptCode populated)
//   hashPrevouts, hashSequence, hashOutputs — precomputed by bip143_tx_hashes
//   sighashType    — typically BIP143_SIGHASH_ALL (0x01)
//   sighash_out    — 32 bytes, receives the sighash
// Explicit-scriptCode variant. `scriptCode` is already varint-prefixed. Used by
// the multisig signer (P2WSH scriptCode = the witness script) and by the
// P2WPKH wrapper below. Returns false if the scriptCode cannot fit the
// preimage buffer — never truncates.
static bool bip143_input_sighash_sc(uint32_t nVersion, uint32_t nLockTime,
                                    const uint8_t outpoint[36], uint32_t nSequence,
                                    uint64_t amount,
                                    const uint8_t *scriptCode, size_t scriptCode_len,
                                    const uint8_t hashPrevouts[32],
                                    const uint8_t hashSequence[32],
                                    const uint8_t hashOutputs[32],
                                    uint32_t sighashType,
                                    uint8_t sighash_out[32]) {
    if (scriptCode_len > BIP143_MAX_SCRIPTCODE) return false;
    uint8_t buf[BIP143_PREIMAGE_CAP];
    size_t off = 0;
    for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((nVersion >> (8*b)) & 0xFF);
    memcpy(buf + off, hashPrevouts, 32); off += 32;
    memcpy(buf + off, hashSequence, 32); off += 32;
    memcpy(buf + off, outpoint, 36); off += 36;
    memcpy(buf + off, scriptCode, scriptCode_len); off += scriptCode_len;
    for (int b = 0; b < 8; b++) buf[off++] = (uint8_t)((amount >> (8*b)) & 0xFF);
    for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((nSequence >> (8*b)) & 0xFF);
    memcpy(buf + off, hashOutputs, 32); off += 32;
    for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((nLockTime >> (8*b)) & 0xFF);
    for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((sighashType >> (8*b)) & 0xFF);
    bip143_dsha256(buf, off, sighash_out);
    return true;
}

// P2WSH scriptCode = varint(len) || witnessScript. Returns bytes written or 0
// if the script cannot fit. out must hold BIP143_MAX_SCRIPTCODE bytes.
static size_t bip143_p2wsh_scriptcode(const uint8_t *witness_script, size_t ws_len,
                                      uint8_t *out) {
    if (ws_len == 0 || ws_len > PSBT_MAX_WITNESS_SCRIPT) return 0;
    size_t p = 0;
    if (ws_len < 0xFD) { out[p++] = (uint8_t)ws_len; }
    else { out[p++] = 0xFD; out[p++] = ws_len & 0xFF; out[p++] = (ws_len >> 8) & 0xFF; }
    memcpy(out + p, witness_script, ws_len);
    return p + ws_len;
}

static void bip143_input_sighash(uint32_t nVersion, uint32_t nLockTime,
                                 const bip143_input_t *input,
                                 const uint8_t hashPrevouts[32],
                                 const uint8_t hashSequence[32],
                                 const uint8_t hashOutputs[32],
                                 uint32_t sighashType,
                                 uint8_t sighash_out[32]) {
    // Preimage layout (BIP-143):
    //   1. nVersion      (4 LE)
    //   2. hashPrevouts  (32)
    //   3. hashSequence  (32)
    //   4. outpoint      (36)
    //   5. scriptCode    (varint-prefixed)
    //   6. value         (8 LE)
    //   7. nSequence     (4 LE)
    //   8. hashOutputs   (32)
    //   9. nLockTime     (4 LE)
    //  10. nHashType     (4 LE)
    // Max size: 4 + 32 + 32 + 36 + 40 + 8 + 4 + 32 + 4 + 4 = 196 bytes
    uint8_t buf[256];
    size_t off = 0;

    // nVersion (4 LE)
    for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((nVersion >> (8*b)) & 0xFF);
    // hashPrevouts (32)
    memcpy(buf + off, hashPrevouts, 32); off += 32;
    // hashSequence (32)
    memcpy(buf + off, hashSequence, 32); off += 32;
    // outpoint (36)
    memcpy(buf + off, input->outpoint, 36); off += 36;
    // scriptCode (already varint-prefixed)
    memcpy(buf + off, input->scriptCode, input->scriptCode_len);
    off += input->scriptCode_len;
    // value (8 LE)
    {
        uint64_t v = input->amount;
        for (int b = 0; b < 8; b++) buf[off++] = (uint8_t)((v >> (8*b)) & 0xFF);
    }
    // nSequence (4 LE)
    {
        uint32_t s = input->nSequence;
        for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((s >> (8*b)) & 0xFF);
    }
    // hashOutputs (32)
    memcpy(buf + off, hashOutputs, 32); off += 32;
    // nLockTime (4 LE)
    for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((nLockTime >> (8*b)) & 0xFF);
    // nHashType (4 LE)
    for (int b = 0; b < 4; b++) buf[off++] = (uint8_t)((sighashType >> (8*b)) & 0xFF);

    bip143_dsha256(buf, off, sighash_out);
}

// ── P2WPKH scriptCode helper ───────────────────────────────────────────
//
// Builds the standard P2WPKH scriptCode from a 20-byte pubkey hash:
//   0x19 0x76 0xa9 0x14 <20 bytes> 0x88 0xac
// = varint(25) || OP_DUP OP_HASH160 PUSH(20) <pkh> OP_EQUALVERIFY OP_CHECKSIG
//
// Writes 26 bytes total. The output buffer must hold ≥26 bytes.
static size_t bip143_p2wpkh_scriptcode(const uint8_t pkh[20], uint8_t *out) {
    out[0] = 0x19;          // varint length = 25
    out[1] = 0x76;          // OP_DUP
    out[2] = 0xa9;          // OP_HASH160
    out[3] = 0x14;          // PUSH 20 bytes
    memcpy(out + 4, pkh, 20);
    out[24] = 0x88;         // OP_EQUALVERIFY
    out[25] = 0xac;         // OP_CHECKSIG
    return 26;
}
