/* ember.h — Emberwill command core: the ops of r7 over the modules
 * ember_hdr (clock), ember_tx / ember_plan (chain), ember_walk (rule),
 * ember_life (tier 3), ember_store (flash). 28 Oct 2026.
 *
 * main.c owns the I2C register file, the doors and the SE sessions; it hands
 * this core fixed-length inputs and calls back for the few things only it can
 * do (the time, entropy, the ceremony's account key, the flash). Every input
 * here arrives at an exact length (r7 "Input rules"); variable data (events,
 * ciphertexts, proofs) is staged through 64-byte chunks into a fixed buffer.
 *
 * Plan ciphertexts ("blobs"): every signed transaction leaves the G0 only as
 *   "EMB1" | k (2) | len (2) | ciphertext (len) | tag (32)
 * keystream = HMAC-SHA256(enc_key, k || ctr) blocks, tag = HMAC-SHA256(mac_key,
 * "EMB1" || k || len || ciphertext); enc_key / mac_key = HMAC-SHA256(blob_key,
 * "ember-enc" / "ember-mac" || plan_id). blob_key is random per plan and never
 * leaves the G0.
 * The ESP32 stores blobs and can lose them, never read or substitute them.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"
#include "ember_hdr.h"
#include "ember_plan.h"
#include "ember_walk.h"
#include "ember_store.h"
#include "ember_life.h"

#define EM_STAGE_MAX    2048u
#define EM_CHUNK        64u
#define EM_BLOB_MAX     (8u + 1100u + 32u)
#define EM_PROOF_LEN    (8u + 80u + 20u * 32u)    /* kind, link, var, depth, index4 | header | branch */
#define EM_STATUS_LEN   96u
#define EM_HDR_IN_LEN   81u                       /* header 80 | quorum 1 */

typedef struct {
    const secp256k1_context *ctx;
    es_flash_t flash;
    uint32_t (*ms)(void *u);                                   /* monotonic milliseconds */
    void     (*rand32)(void *u, uint8_t out[32]);              /* entropy */
    /* ceremony only: leaf key of the account the BTC door opened. 0 ok */
    int      (*leaf)(void *u, uint32_t change, uint32_t index, uint8_t key[32], uint8_t pub33[33]);
    void *u;
} em_env_t;

enum {
    EM_OK = 0,
    EM_E_NOPLAN = -20, EM_E_PLAN = -21, EM_E_STATE = -22, EM_E_FLASH = -23, EM_E_LEN = -24,
    EM_E_CEREMONY = -25, EM_E_RULE = -26, EM_E_BLOB = -27, EM_E_PROOF = -28, EM_E_OWNER = -29, EM_E_AE = -30,
};

/* params: &EH_MAINNET in an image; test params on the host. compiled: the image's anchor. */
void em_boot(const em_env_t *env, const eh_params_t *params, const eh_anchor_t *compiled);

/* EMBER_HEADER: one header plus the ESP32's relay-quorum flag. Returns the
 * header clock's code (EH_*). Runs the walk and persists when due. */
int  em_header(const uint8_t in[EM_HDR_IN_LEN]);

/* Staging: 64-byte chunks of a variable item (event, blob, proof). */
int  em_stage_begin(uint16_t total);
int  em_stage_chunk(uint16_t index, const uint8_t data[EM_CHUNK]);
uint16_t em_stage_total(void);
void em_stage_reset(void);

/* EMBER_PROOF from the stage (exactly EM_PROOF_LEN). */
int  em_proof(void);
/* EMBER_LIFE from the stage (serialised event) + 64-byte signature. */
int  em_life(const uint8_t sig[64]);
/* Life the G0 sees itself (main.c calls these from its own paths). */
void em_life_tier1(const uint8_t owner_xonly[32]);   /* NULL in a BTC life (spend PIN): no key to bind */
void em_life_tier2(void);
/* EMBER_AWAY: height (4 bytes LE). main.c gates on tier-1 life this power-on. */
int  em_away(uint32_t height);
/* EMBER_RELEASE: the blob in the stage, if the rule allows exactly that
 * transaction now. Writes the signed transaction to out. */
int  em_release(uint8_t *out, size_t cap, size_t *outlen);
/* EMBER_PULSE: serialise the Pulse to sign (owner key bound, within one
 * Quiet of the last PIN). id = the event id main.c signs with anti-exfil. */
int  em_pulse(uint8_t *ser, size_t cap, size_t *len, uint8_t id[32]);
/* EMBER_STATUS */
void em_status(uint8_t out[EM_STATUS_LEN]);
/* EMBER_SAVE: persist the clock's restart point now (rate-limited to real progress) */
int  em_save(void);
/* EMBER_CLEAR */
int  em_clear(void);

/* Ceremony (BTC door, spend PIN, account key held by main.c):
 *   em_set(wire)      validate, build every transaction, fresh plan_id / blob_key
 *   em_cer_init(h)    next signature: anti-exfil commit -> R0 (33), and which (k, input)
 *   em_cer_finish(t)  tweak, sign, verify; out: r (32) for the host check, and
 *                     a blob when transaction k is complete (blob_len 0 otherwise)
 *   em_commit()       after the last blob: write the plan page and the first state
 * Anything else, or a timeout in main.c, calls em_cer_abort(). */
int  em_set(const uint8_t wire[EP_SET_LEN]);
int  em_cer_init(const uint8_t h[32], uint8_t r0[33], uint16_t *k, uint8_t *input);
/* v20 (20 Nov 2026): after em_cer_init, what is about to be signed, for the
 * ESP32 to check against the plan on its own before EM_CER_FIN: the BIP-143
 * digest of this input, and on a transaction's first input its UNSIGNED
 * serialisation (no witness: it cannot be broadcast). Never a signature: the
 * ESP32 still never holds a signed transaction before the release rule allows
 * it (decision 4). txlen 0 on the later inputs of a transaction. */
int  em_cer_peek(uint8_t sh[32], uint8_t *tx, size_t cap, size_t *txlen);
uint32_t em_cer_tip0(void);   /* the ceremony tip the plan's locktimes count from (0 if none) */
int  em_cer_finish(const uint8_t t[32], uint8_t r32[32], uint8_t *blob, size_t cap, size_t *blob_len);
int  em_commit(void);
void em_cer_abort(void);

/* for tests */
const ew_state_t *em_walk(void);
const eh_chain_t *em_chain(void);
uint32_t em_tx_count(void);
/* the ceremony in progress: transactions and signatures it will take (0 if none) */
void em_cer_counts(uint32_t *ntx, uint32_t *nsig);
uint32_t em_blob_index(ew_release_t r);
