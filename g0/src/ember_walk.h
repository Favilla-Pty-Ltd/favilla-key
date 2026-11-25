/* ember_walk.h — the chain-walk rule: life, refresh, Afterglow, Kindling.
 * 28 Oct 2026. Spec: Emberwill v0.4 r7 "Life is a height", "The chain walk",
 * "Silence: Afterglow and Kindling", "Away date".
 *
 * Pure logic over heights the header clock (ember_hdr) has verified and
 * powered seconds counted by the G0's own tick. No I/O, no keys: the command
 * layer feeds events in and acts on what ew_next() allows.
 *
 * Life (all heights):
 *   tier 1  PIN-gated fetch on this device        moves last_life, last_tier1, last_pulse
 *   tier 2  device-approved signature (flag)       moves last_life, capped at last_tier1 + Quiet
 *   pulse   G0-built Pulse, pinned to a block      moves last_life, last_pulse
 *   note    owner-signed note, created_at height   moves last_life, capped at last_pulse + Quiet
 *   away    PIN in person, future height           moves last_life up to tip + 1 year
 * The walk (link i, X_i = X0 + i*Quiet):
 *   refresh R(i+1) may be released while  tip >= X_i - Quiet/2  and  tip - last_life < Quiet/2
 *   a refresh proved 3 deep advances the link; a reorg before 6 deep undoes it
 *   silent: tip - last_life >= Quiet. Afterglow: 1008 blocks AND 7 days of powered,
 *   quorum-confirmed time since silence began (dark time never counts)
 *   Kindling: Afterglow served and tip >= X_i: release C_i variant 0, then the next
 *   variant every 36 blocks unconfirmed; a coupon proved 6 deep ends the plan.
 */
#pragma once
#include <stdint.h>

#ifdef EMBER_BENCH_FUSE                /* short-fuse bench build, see ember_plan.h */
#define EW_AFTERGLOW_BLOCKS 6u
#define EW_AFTERGLOW_SECS   3600u
#define EW_RBF_BLOCKS       3u
#else
#define EW_AFTERGLOW_BLOCKS 1008u
#define EW_AFTERGLOW_SECS   (1008u * 600u)
#define EW_RBF_BLOCKS       36u
#endif
#define EW_TICK_CAP_SECS    1800u      /* one quorum report credits at most 30 min */
#define EW_ADV_DEPTH        3u
#define EW_FINAL_DEPTH      6u
#define EW_AWAY_MAX         52560u     /* one year of blocks */
#define EW_CVARS            3u

enum { EW_LIFE_NONE = 0, EW_LIFE_TIER1 = 1, EW_LIFE_TIER2 = 2, EW_LIFE_PULSE = 3, EW_LIFE_NOTE = 4, EW_LIFE_AWAY = 5 };

typedef struct {
    /* plan constants */
    uint32_t nlinks, quiet, x0;
    /* walk */
    uint32_t link;
    uint32_t last_life, last_tier1, last_pulse;
    uint8_t  life_kind;
    uint8_t  adv_pending;  uint32_t adv_height;  uint8_t adv_block[32];
    /* Afterglow */
    uint32_t ag_secs;
    /* Kindling */
    uint8_t  kindled, kvar;  uint32_t kheight;
    uint8_t  done_pending, done;  uint32_t done_height;  uint8_t done_block[32];
} ew_state_t;

/* Main-chain lookup the walk needs from the header clock: confirmations of a
 * block on the main branch (1 = tip), 0 if it is not there. */
typedef uint32_t (*ew_conf_fn)(void *ctx, const uint8_t hash[32]);

void ew_init(ew_state_t *w, uint32_t nlinks, uint32_t quiet, uint32_t x0, uint32_t ceremony_tip);
uint32_t ew_x(const ew_state_t *w, uint32_t i);

/* Life events. h is the height the event is pinned to (tip for tier 1/2,
 * the Pulse's block, the note's created_at height, the away height). Returns
 * 1 if last_life moved. Away is refused (-1) beyond tip + one year. */
int  ew_life(ew_state_t *w, int kind, uint32_t h, uint32_t tip);

/* Powered time: secs since the last report, quorum = the ESP32 sees its relay
 * quorum. Only counts while silent and not yet kindled. */
void ew_tick(ew_state_t *w, uint32_t secs, int quorum, uint32_t tip);

/* After every header: re-check pending advances and the kindling proof
 * against the main branch (undo on reorg, settle at 6 deep). */
void ew_on_tip(ew_state_t *w, uint32_t tip, ew_conf_fn conf, void *ctx);

/* A Merkle-proved transaction in a main-branch block. which: 'R' with the
 * refresh index it matched, or 'C' with the coupon link. Returns 1 if the
 * state changed. */
int  ew_proof(ew_state_t *w, char which, uint32_t idx, const uint8_t block[32], uint32_t conf, uint32_t block_height);

/* What may be released now. */
enum { EW_NOTHING = 0, EW_REFRESH = 1, EW_COUPON = 2 };
typedef struct { int what; uint32_t link; uint32_t var; } ew_release_t;
ew_release_t ew_next(const ew_state_t *w, uint32_t tip);
/* Call when a release was handed out (moves Kindling state). */
void ew_released(ew_state_t *w, ew_release_t r, uint32_t tip);

int ew_silent(const ew_state_t *w, uint32_t tip);
int ew_afterglow_served(const ew_state_t *w, uint32_t tip);
/* EMBER_PULSE gate (r7): the G0 builds Pulses only within one Quiet of the last PIN. */
int ew_pulse_allowed(const ew_state_t *w, uint32_t tip);
