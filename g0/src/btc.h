/* =============================================================================
 * btc.h — v3: Bitcoin key derivation + BIP-143 signing INSIDE the G0
 * =============================================================================
 *
 * The seed is plaintext only in this chip. The ESP32 parses the PSBT, does the
 * user-facing verification, and hands this chip a FIXED-LENGTH signing request
 * (BTC_REQ_LEN bytes, invariant 1: no parser on the G0). This chip:
 *   1. derives the leaf key itself from the seed + (change, index) in the
 *      request — it never accepts a private key or a path prefix over the bus,
 *      only the two non-hardened indices;
 *   2. recomputes the BIP-143 sighash from the request (the ESP32 never sends
 *      a bare hash to sign — for P2WPKH the scriptCode comes from the pubkey
 *      this chip just derived; for P2WSH from the witnessScript in the request);
 *   3. signs with libsecp256k1 (low-S) using an ANTI-EXFIL nonce: k0 is RFC 6979
 *      over (leaf key, sighash, host commitment h) and the host's revealed t
 *      tweaks it (src/antiexfil.c, 27 Oct 2026). Returns the compressed pubkey,
 *      the DER signature and the sighash it signed (so the ESP32 can cross-check
 *      against its own bip143.h — a field KAT) and checks x(R0 + H(R0||t)G) == r.
 *
 * SIGN REQUEST (BTC_IN, exactly BTC_REQ_LEN = 416 bytes, little-endian ints):
 *   off  len
 *   0    1    kind: 1 = BIP-84 P2WPKH  m/84'/0'/0'/change/index
 *                   2 = BIP-48 P2WSH   m/48'/0'/0'/2'/change/index (sortedmulti cosigner)
 *   1    1    sighash type — must be 0x01 (SIGHASH_ALL)
 *   2    2    witness_script_len (P2WSH only; 0 for P2WPKH), <= BTC_WS_MAX
 *   4    4    nVersion
 *   8    4    nLockTime
 *   12   32   hashPrevouts
 *   44   32   hashSequence
 *   76   32   hashOutputs
 *   108  36   outpoint (txid as in the tx || vout LE)
 *   144  4    nSequence
 *   148  8    amount (sats)
 *   156  4    change (0 or 1)
 *   160  4    index  (< 0x80000000)
 *   164  252  witness_script, zero-padded
 *
 * DOORKEYS OUTPUT (what the ESP32 needs for a BTC life without the seed):
 *   master fingerprint, the two account xpubs (public key, chain code, parent
 *   fingerprint — depth/child number are fixed by the path) and the sealed-
 *   state key HMAC-SHA256(seed, "FAVILLA-BTC-STATE-v1"). See main.c for the
 *   register layout.
 * ========================================================================== */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"
#include "secp256k1_recovery.h"

#define BTC_REQ_LEN      416
#define BTC_WS_MAX       252
#define BTC_KIND_P2WPKH  1
#define BTC_KIND_P2WSH   2
#define BTC_SIGHASH_ALL  0x01
#define BTC_DER_MAX      72

typedef struct { uint8_t key[32]; uint8_t cc[32]; } btc_xprv;

/* Account-level result: everything the ESP32 keeps for the life. */
typedef struct {
    uint8_t pub[33];
    uint8_t cc[32];
    uint8_t parent_fp[4];
} btc_xpub_t;

/* m/84'/0'/0' (purpose 84) or m/48'/0'/0'/2' (purpose 48). Fills the account
 * xprv, the master fingerprint and the account's parent fingerprint (either
 * may be NULL to skip its pubkey computation). 0 on ok. */
int btc_account(const secp256k1_context *ctx, const uint8_t seed[64], int purpose,
                btc_xprv *acct, uint8_t master_fp[4], uint8_t parent_fp[4]);

/* Emberwill (28 Oct 2026): leaf key m/84'/0'/0'/change/index from an account
 * xprv already in RAM (the ceremony holds the account, not the seed). 0 ok. */
int btc_leaf(const secp256k1_context *ctx, const btc_xprv *acct, uint32_t change, uint32_t index,
             uint8_t key[32], uint8_t pub33[33]);

/* Public image of an xprv. */
int btc_xpub_of(const secp256k1_context *ctx, const btc_xprv *x, const uint8_t parent_fp[4], btc_xpub_t *out);

/* ── signing, split for anti-exfil (27 Oct 2026) ─────────────────────────────
 * The nonce is never chosen here: src/antiexfil.c derives k0 from the leaf
 * key + sighash + the host's commitment h, and the signature is made with the
 * host-tweaked k. btc.c only derives (prepare) and checks + serialises
 * (release).
 *
 * prepare: validate the request, derive m/84'/0'/0'/change/index (or the
 * BIP-48 cosigner leaf), output the 32-byte leaf key, its compressed pubkey
 * and the BIP-143 sighash. 0 ok, -1 bad request field, -2 derivation failed.
 * release: verify-before-release (re-derived pubkey must match, signature
 * must verify) then DER. 0 ok, -3 sign/verify failed, -4 DER failed. */
int btc_sign_prepare(const secp256k1_context *ctx, const uint8_t seed[64],
                     const uint8_t req[BTC_REQ_LEN],
                     uint8_t leaf_key[32], uint8_t pub33[33], uint8_t sighash32[32]);
int btc_sign_release(const secp256k1_context *ctx, const uint8_t leaf_key[32],
                     const uint8_t sighash32[32], const uint8_t pub33[33],
                     const secp256k1_ecdsa_signature *sig,
                     uint8_t der[BTC_DER_MAX], uint8_t *der_len);

/* ── BIP-137 message signing (15 Oct 2026) ───────────────────────────────────
 * MESSAGE REQUEST (BTC_IN, same 416-byte register as a sign request):
 *   off  len
 *   0    4    "FMSG"
 *   4    1    version = 1
 *   5    1    change (0 or 1)        path m/84'/0'/0'/change/index (P2WPKH only)
 *   6    4    index LE (< 0x80000000)
 *   10   1    message length, 1..BTC_MSG_MAX
 *   11   len  message bytes, printable ASCII 0x20..0x7E only; rest zero
 * This chip builds the digest itself:
 *   SHA256d( 0x18 "Bitcoin Signed Message:\n" || varint(len) || message )
 * and never accepts a hash. The fixed prefix is the domain separation that
 * keeps a message signature from ever being a transaction signature: an ESP32
 * cannot pass a transaction sighash off as a "message".
 * Output: pub33, the 65-byte BIP-137 signature (header 39 + recid = P2WPKH,
 * then r || s, low-S) and the digest it signed, so the ESP32 can recompute and
 * compare. The signature is checked by public-key recovery before it is
 * released. prepare: 0 ok, -1 bad request, -2 derivation. release: 0 ok,
 * -3 serialise, -4 self-check. */
#define BTC_MSG_MAX      240
int btc_msg_request_valid(const uint8_t req[BTC_REQ_LEN]);   /* 1 = well-formed (checked before the seed fetch) */
int btc_msg_prepare(const secp256k1_context *ctx, const uint8_t seed[64],
                    const uint8_t req[BTC_REQ_LEN],
                    uint8_t leaf_key[32], uint8_t pub33[33], uint8_t digest32[32]);
int btc_msg_release(const secp256k1_context *ctx, const uint8_t digest32[32],
                    const uint8_t pub33[33], const secp256k1_ecdsa_recoverable_signature *rs,
                    uint8_t sig65[65]);

#ifdef BTC_HOST_REFERENCE
/* Host tests only: the untweaked RFC 6979 reference (prepare + libsecp256k1
 * default nonce + release). Never compiled into firmware. */
int btc_sign_request(const secp256k1_context *ctx, const uint8_t seed[64],
                     const uint8_t req[BTC_REQ_LEN],
                     uint8_t pub33[33], uint8_t der[BTC_DER_MAX], uint8_t *der_len,
                     uint8_t sighash32[32]);
int btc_sign_message(const secp256k1_context *ctx, const uint8_t seed[64],
                     const uint8_t req[BTC_REQ_LEN],
                     uint8_t pub33[33], uint8_t sig65[65], uint8_t digest32[32]);
#endif

/* Sealed-state key: HMAC-SHA256(seed, "FAVILLA-BTC-STATE-v1"). */
void btc_state_key(const uint8_t seed[64], uint8_t out[32]);
