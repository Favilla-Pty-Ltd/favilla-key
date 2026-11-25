/* ember_tx.h — the only transaction shapes Emberwill ever signs. 28 Oct 2026.
 *
 * Every transaction in a plan is built inside the G0 from data it generated
 * itself or took from fixed-size EMBER_SET slots (r7 "Input rules"):
 *   coupon  C: P2WPKH inputs (the estate coins, or the previous refresh's
 *              output) -> heirs (standard scriptPubKeys from 34-byte slots)
 *              + the executor's bump output
 *   refresh R: P2WPKH inputs -> one P2WPKH output to the owner's next address
 * Version 2, every input nSequence 0xFFFFFFFD (RBF on, nLockTime enforced),
 * height nLockTime, SIGHASH_ALL, BIP-143 sighash, witness [sig, pubkey].
 *
 * Nothing here parses a transaction. Serialisation streams into a SHA-256
 * context (txid, sighash) or a caller buffer, so no full-size copy is needed.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define ET_MAX_IN    3
#define ET_MAX_OUT   7     /* 6 heirs + bump */
#define ET_SEQ_RBF   0xFFFFFFFDu
#define ET_SIG_MAX   73    /* DER (<= 72) + sighash byte */

typedef struct {
    uint8_t  txid[32];     /* internal byte order */
    uint32_t vout;
    uint64_t amount;
    uint32_t seq;
    uint8_t  pub[33];      /* compressed key the input pays to (P2WPKH) */
    uint8_t  sig[ET_SIG_MAX];
    uint8_t  siglen;       /* 0 until signed */
} et_in_t;

typedef struct {
    uint64_t amount;
    uint8_t  spk[34];
    uint8_t  spklen;
} et_out_t;

typedef struct {
    uint32_t version, locktime;
    uint8_t  nin, nout;
    et_in_t  in[ET_MAX_IN];
    et_out_t out[ET_MAX_OUT];
} et_tx_t;

/* A 34-byte heir slot holds a scriptPubKey left-aligned, zero-padded. Returns
 * its length if it is one of the standard templates (P2WPKH 22, P2WSH 34,
 * P2TR 34, P2PKH 25, P2SH 23), 0 otherwise. Template match only. */
uint8_t et_spk_len(const uint8_t slot[34]);

/* P2WPKH scriptPubKey for a compressed pubkey: 00 14 <hash160(pub)>. */
void et_p2wpkh_spk(const uint8_t pub[33], uint8_t spk[22]);

/* Serialised length; with_witness uses the signatures present. */
size_t et_serialize(const et_tx_t *tx, int with_witness, uint8_t *buf, size_t cap);
void   et_txid(const et_tx_t *tx, uint8_t out[32]);
/* BIP-143 SIGHASH_ALL digest for input i (P2WPKH scriptCode from in[i].pub). */
void   et_sighash(const et_tx_t *tx, int i, uint8_t out[32]);
/* Upper bound on virtual size with every signature at the 72-byte DER maximum. */
uint32_t et_vsize_max(const et_tx_t *tx);
/* Sum of inputs minus sum of outputs, or -1 if outputs exceed inputs. */
int64_t  et_fee(const et_tx_t *tx);
