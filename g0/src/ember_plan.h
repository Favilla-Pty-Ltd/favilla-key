/* ember_plan.h — the estate plan: what EMBER_SET carries and the chain of
 * transactions the G0 builds from it. 28 Oct 2026.
 *
 * Decisions of 28 Oct 2026 (spec findings):
 *   - one fee per refresh (r7's two variants make link i need 2^i copies)
 *   - heir shares in basis points of (input - fee - bump), dust to heir 1
 *   - three coupon fee variants, all spending the same refresh output
 *
 * The chain, for link i = 0..N (X0 = ceremony tip + Quiet + Afterglow):
 *   C0[v]  spends the estate coins            -> heirs + bump   nLockTime X0
 *   R1     spends the estate coins            -> owner addr 0   nLockTime X0 - Quiet/2
 *   Ci[v]  spends Ri:0                        -> heirs + bump   nLockTime Xi = X0 + i*Quiet
 *   Ri+1   spends Ri:0                        -> owner addr i   nLockTime Xi - Quiet/2
 * Every transaction is built from this struct, the ceremony tip and public
 * keys the G0 derived itself; none of it is parsed from the ESP32.
 */
#pragma once
#include <stdint.h>
#include "ember_tx.h"

#define EP_MAX_COINS   3
#define EP_MAX_HEIRS   6
#define EP_MAX_LINKS   8
#define EP_CVARS       3
#ifdef EMBER_BENCH_FUSE
/* Short-fuse BENCH build (28 Oct 2026): the whole lifecycle in an afternoon on
 * mainnet with real sats. Quiet 12 blocks, Afterglow 6 blocks + 1 h powered,
 * RBF every 3 blocks. Same code as production; only these numbers differ.
 * Never freeze, never ship: pio run -e g0_fuse. */
#define EP_AFTERGLOW   6u
#define EP_QUIET_MIN   12u
#else
#define EP_AFTERGLOW   1008u
#define EP_QUIET_MIN   4032u         /* 4 weeks: below this the Afterglow dominates */
#endif
#define EP_DUST        546u          /* conservative for every allowed template */
#define EP_QUIET_MAX   105120u       /* about 2 years */
#define EP_RATE_MAX    2000u         /* sat/vB */
#define EP_MAX_SATS    2100000000000000ull

/* EMBER_SET body: fixed layout, every field at a fixed offset (see ep_set_parse). */
typedef struct {
    uint8_t  ncoins, nheirs, nlinks;
    struct { uint8_t txid[32]; uint32_t vout; uint64_t amount; uint32_t change, index; } coin[EP_MAX_COINS];
    struct { uint8_t spk[34]; uint16_t bp; } heir[EP_MAX_HEIRS];
    uint8_t  exec_spk[34];
    uint32_t quiet;                  /* blocks */
    uint32_t ref_index;              /* first receive index (m/84'/0'/0'/0/i) for refresh outputs */
    uint16_t crate[EP_CVARS];        /* coupon fee rates, sat/vB, ascending */
    uint16_t rrate;                  /* refresh fee rate, sat/vB */
    uint32_t bump;                   /* executor bump output, sats */
} ep_set_t;

#define EP_SET_LEN 430   /* bytes on the wire, see ep_set_parse */

enum { EP_OK = 0, EP_E_COUNT = -1, EP_E_SPK = -2, EP_E_BP = -3, EP_E_QUIET = -4, EP_E_RATE = -5,
       EP_E_AMOUNT = -6, EP_E_DUST = -7, EP_E_DERIV = -8, EP_E_DUPCOIN = -9, EP_E_LEN = -10, EP_E_PAD = -11 };

/* Fixed-offset copy of the wire bytes into the struct. Reads nothing beyond
 * the fixed fields; length must be exactly EP_SET_LEN. Reserved bytes must be
 * zero. Returns EP_OK or an error (it does not validate semantics). */
int ep_set_parse(const uint8_t *b, size_t len, ep_set_t *s);

/* Semantic checks that need no keys: counts, templates, shares, rates, and
 * that every transaction of every link (all variants) has outputs at or
 * above dust once fees are paid. tip is the ceremony tip (for X0 overflow). */
int ep_validate(const ep_set_t *s, uint32_t tip);

/* Which transaction. kind: 'C' coupon (link 0..N, variant 0..2) or 'R' refresh (link 1..N). */
typedef struct { uint8_t kind, link, var; } ep_id_t;

/* Number of transactions in the plan and the canonical order (index -> id):
 * C0v0 C0v1 C0v2 | R1 C1v0 C1v1 C1v2 | R2 ... */
uint32_t ep_count(const ep_set_t *s);
ep_id_t  ep_id_at(uint32_t k);

/* Build one transaction, unsigned (siglen 0), with real txids for its inputs.
 * coin_pub: the pubkey of each estate coin; ref_pub[i]: owner address i
 * (refresh R(i+1) pays to it, coupon C(i+1) spends it). */
int ep_build(const ep_set_t *s, uint32_t tip, const uint8_t coin_pub[EP_MAX_COINS][33],
             const uint8_t ref_pub[EP_MAX_LINKS][33], ep_id_t id, et_tx_t *tx);

uint32_t ep_x(const ep_set_t *s, uint32_t tip, uint32_t i);   /* X_i */
