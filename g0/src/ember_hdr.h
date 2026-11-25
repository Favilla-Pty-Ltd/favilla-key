/* ember_hdr.h — Emberwill header clock: the G0 reads time off Bitcoin.
 * 28 Oct 2026. Spec: Emberwill v0.4 r7, "The watcher: a clock and a pulse".
 *
 * The ESP32 feeds one 80-byte header at a time (EMBER_HEADER). For each one
 * this module checks, exactly as Bitcoin Core does for a mainnet header:
 *   - the previous-hash link (to the tip, or to a recent block for a reorg)
 *   - proof of work: SHA-256d of the header at or below the nBits target,
 *     nBits well formed and not easier than the pow limit
 *   - nBits: equal to the parent's inside a period; at every 2,016th block
 *     exactly the retarget of the parent's target by the last period's
 *     timespan (clamped x4 either way), Core's off-by-one included
 *   - timestamp strictly above the median of the previous 11 (MTP)
 *   - minimum version by height (BIP34 / BIP66 / BIP65)
 * Not checked, by design: "no more than 2 h in the future". The G0 has no
 * clock; that rule needs one. A header far in the future still needs real
 * proof of work, so the cost of lying about time stays mining.
 *
 * The chain starts from an anchor compiled into the image (height, hash,
 * nBits, period start time, the last 11 timestamps). Nothing before the
 * anchor is ever accepted.
 *
 * Reorgs: the main branch keeps the last EH_RING blocks. A header that
 * connects to one of those (not the tip) starts a candidate branch; the
 * candidate replaces the main branch the moment it has strictly more work
 * since the fork point (first seen wins ties, as in Core). A fork deeper than
 * the ring allows is refused: the G0 then stays on what it has (delay, never
 * advance).
 *
 * Input rule (r7 "Input rules"): the header is 80 bytes at fixed offsets and
 * nothing in it is parsed beyond reading those fields.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define EH_RING      24   /* blocks kept per branch: reorg depth up to EH_RING-11 = 13 */
#define EH_MTP_SPAN  11

typedef struct {
    uint32_t pow_limit[8];        /* little-endian 32-bit limbs */
    uint32_t interval;            /* 2016 */
    uint32_t timespan;            /* 1209600 s */
    uint8_t  no_retarget;         /* regtest-style test params only */
    uint32_t v2_height, v3_height, v4_height;   /* BIP34, BIP66, BIP65 activation */
} eh_params_t;

extern const eh_params_t EH_MAINNET;

typedef struct {
    uint32_t height;
    uint8_t  hash[32];            /* internal byte order (as SHA-256d outputs it) */
    uint32_t bits;
    uint32_t pstart;              /* timestamp of the first block of the anchor's period */
    uint8_t  ntimes;              /* 1..11 */
    uint32_t times[EH_MTP_SPAN];  /* times[ntimes-1] is the anchor's own timestamp */
} eh_anchor_t;

typedef struct {
    uint8_t  hash[32];            /* all zero: timestamp-only entry from the anchor, not a fork point */
    uint32_t time, bits, pstart;
} eh_ent_t;

typedef struct {
    eh_ent_t r[EH_RING];          /* block at height h lives in r[h % EH_RING] */
    uint32_t tip;                 /* tip height */
    uint32_t n;                   /* entries valid, counting back from the tip (<= EH_RING) */
    uint32_t fork;                /* candidate only: height of the block it forked from */
    uint8_t  live;                /* candidate only */
} eh_branch_t;

typedef struct {
    const eh_params_t *p;
    uint32_t     floor_height;    /* the anchor height: nothing at or below it is replaced */
    uint32_t     base;            /* lowest height with a stored timestamp */
    uint32_t     last_fork;       /* fork height of the most recent reorg */
    eh_branch_t  main, cand;
} eh_chain_t;

enum {
    EH_TIP      = 0,    /* extended the main branch */
    EH_REORG    = 1,    /* candidate overtook main: main replaced; see eh_last_fork() */
    EH_SIDE     = 2,    /* accepted onto the candidate branch, main unchanged */
    EH_DUP      = 3,    /* already have it (main or candidate) */
    EH_E_ORPHAN = -1,   /* parent unknown (not in the ring) */
    EH_E_POW    = -2,   /* hash above target, or nBits malformed / easier than limit */
    EH_E_BITS   = -3,   /* nBits not the value the retarget rule requires */
    EH_E_TIME   = -4,   /* timestamp at or below median time past */
    EH_E_VER    = -5,   /* version below the height's minimum */
    EH_E_DEEP   = -6,   /* fork point too deep for the ring to check MTP */
};

void     eh_init(eh_chain_t *c, const eh_params_t *p, const eh_anchor_t *a);
int      eh_connect(eh_chain_t *c, const uint8_t hdr[80]);
uint32_t eh_last_fork(const eh_chain_t *c);
const eh_ent_t *eh_tip(const eh_chain_t *c);
uint32_t eh_tip_height(const eh_chain_t *c);
/* Median time past of the main tip (what the next block must exceed). */
uint32_t eh_tip_mtp(const eh_chain_t *c);

/* Is `hash` a block on the main branch still in the ring? Returns its height
 * through *height and the confirmation count (1 = the tip) or 0 if not found. */
uint32_t eh_find_main(const eh_chain_t *c, const uint8_t hash[32], uint32_t *height);

/* Merkle inclusion: does txid (internal order) at position `index` hash up to
 * `root` through `depth` (0..20) sibling hashes? 1 if yes. */
#define EH_MERKLE_MAX_DEPTH 20
int eh_merkle_check(const uint8_t txid[32], uint32_t index, uint8_t depth,
                    const uint8_t branch[][32], const uint8_t root[32]);

/* Exposed for the host tests (consensus arithmetic, byte-exact with Core). */
void     eh_hash(const uint8_t hdr[80], uint8_t out[32]);
int      eh_bits_to_target(uint32_t bits, uint32_t t[8]);           /* 0 if negative / overflow / zero */
uint32_t eh_target_to_bits(const uint32_t t[8]);
uint32_t eh_retarget(const eh_params_t *p, uint32_t last_bits, uint32_t first_time, uint32_t last_time);
void     eh_work(uint32_t bits, uint32_t w[8]);                     /* 2^256 / (target+1) */
