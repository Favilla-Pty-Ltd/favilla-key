/* ember_life.h — tier-3 life: an owner-signed Nostr event, judged in the G0.
 * 28 Oct 2026. Spec: r7 "Life is a height" tier 3, "The Pulse", input rules.
 *
 * The ESP32 streams the NIP-01 serialisation of the event,
 *     [0,"<pubkey hex>",<created_at>,<kind>,<tags>,"<content>"]
 * (at most EL_MAX bytes) plus its 64-byte signature. The G0:
 *   - hashes the whole serialisation (that hash IS the event id) and verifies
 *     the BIP-340 signature over it against the owner's x-only pubkey;
 *   - reads only fixed-position fields: the 4-byte prefix, the 64 hex chars of
 *     the pubkey (must be the owner's, lower-case), created_at and kind as
 *     bounded digit runs (<= 10 and <= 5 digits, no leading zeros);
 *   - for a Pulse (kind EL_PULSE_KIND) requires the remainder to be exactly
 *     ,[],"<64 hex block hash>"]  so the block hash is at a fixed offset too.
 * Nothing else in the event is looked at. Tags and content of notes are hashed,
 * never parsed.
 *
 * Kinds that count (r7 tier 3, human-authored only): 1 note, 30023 long-form,
 * 0 profile, 3 contact list, plus the Pulse. Reactions, zap requests and
 * anything a bunker auto-signs do not.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"

#define EL_MAX          2048u
#define EL_PULSE_KIND   8333u      /* PROVISIONAL: the protocol note fixes the number */
#define EL_FUTURE_SECS  7200u      /* created_at may lead the tip's header time by 2 h at most */

enum { EL_NOTE = 1, EL_PULSE = 2,
       EL_E_SHAPE = -1, EL_E_KEY = -2, EL_E_SIG = -3, EL_E_KIND = -4, EL_E_FUTURE = -5, EL_E_LEN = -6 };

typedef struct {
    uint32_t created_at;
    uint32_t kind;
    uint8_t  block[32];      /* Pulse only: the block hash it pins to (internal byte order) */
    uint8_t  id[32];
} el_event_t;

/* Checks shape, owner key and signature. Returns EL_NOTE or EL_PULSE, or an error. */
int el_check(const secp256k1_context *ctx, const uint8_t *ser, size_t len, const uint8_t sig[64],
             const uint8_t owner_xonly[32], el_event_t *ev);

/* Height a note's created_at is pinned to, judged against the tip header's
 * time. Conservative: rounds toward older. EL_E_FUTURE if created_at is more
 * than 2 h past the tip's time. */
int el_note_height(uint32_t created_at, uint32_t tip, uint32_t tip_time, uint32_t floor_height, uint32_t *h);

/* Serialise a Pulse for signing inside the G0: content = hex of the block hash
 * (display order, as every explorer shows it), empty tags. Returns length. */
size_t el_pulse_serialise(const uint8_t owner_xonly[32], uint32_t created_at, const uint8_t block[32], uint8_t *out, size_t cap);
