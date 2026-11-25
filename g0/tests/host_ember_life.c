/* host_ember_life.c — tier-3 life events against embit-signed Nostr events.
 * 28 Oct 2026. tests/run_ember_life.sh. */
#include "ember_life.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "sha256.h"
#include "data/life_vectors.h"
#include <stdio.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, ...) do { if (c) pass++; else { fail++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    printf("Emberwill tier-3 life events, host tests\n");
    int notes = 0, pulses = 0, refused = 0;
    for (size_t i = 0; i < sizeof LIFE / sizeof LIFE[0]; i++) {
        const life_vec_t *v = &LIFE[i]; el_event_t ev;
        int rc = el_check(ctx, (const uint8_t *)v->ser, v->len, v->sig, LIFE_OWNER, &ev);
        CHECK(rc == v->want, "event %zu: %d want %d (%.60s)", i, rc, v->want, v->ser);
        if (rc > 0) {
            CHECK(ev.created_at == v->created && ev.kind == v->kind, "event %zu fields", i);
            if (rc == EL_PULSE) CHECK(!memcmp(ev.block, v->block, 32), "event %zu pulse block", i);
            notes += rc == EL_NOTE; pulses += rc == EL_PULSE;
        } else refused++;
        /* every single-byte change to an accepted event is refused */
        if (rc > 0 && i % 10 == 0) {
            uint8_t buf[EL_MAX]; int caught = 0;
            for (size_t k = 0; k < v->len; k++) { memcpy(buf, v->ser, v->len); buf[k] ^= 0x01; caught += el_check(ctx, buf, v->len, v->sig, LIFE_OWNER, &ev) < 0; }
            CHECK(caught == v->len, "event %zu: %d/%u byte flips refused", i, caught, v->len);
        }
    }
    printf("  embit-signed: %d notes and %d Pulses accepted, %d crafted events refused\n", notes, pulses, refused);

    /* a Pulse the G0 serialises and signs itself verifies through the same check */
    uint8_t blk[32], ser[256], sig[64]; for (int i = 0; i < 32; i++) blk[i] = (uint8_t)(i * 7 + 1);
    size_t n = el_pulse_serialise(LIFE_OWNER, 1761650000, blk, ser, sizeof ser);
    uint8_t id[32]; sha256(ser, n, id);
    secp256k1_keypair kp; CHECK(secp256k1_keypair_create(ctx, &kp, LIFE_OWNER_SK), "keypair");
    CHECK(secp256k1_schnorrsig_sign32(ctx, sig, id, &kp, NULL), "sign");
    el_event_t ev; int rc = el_check(ctx, ser, n, sig, LIFE_OWNER, &ev);
    CHECK(rc == EL_PULSE && !memcmp(ev.block, blk, 32) && ev.created_at == 1761650000, "self-built Pulse round trip (%d)", rc);
    printf("  self-built Pulse: %.*s\n", (int)n, ser);

    /* created_at -> height, judged against the tip header's time */
    uint32_t h;
    CHECK(el_note_height(1000 + 7200, 900000, 1000, 880000, &h) == 0 && h == 900000, "2 h ahead accepted, pinned at tip");
    CHECK(el_note_height(1000 + 7201, 900000, 1000, 880000, &h) == EL_E_FUTURE, "more than 2 h ahead refused");
    CHECK(el_note_height(1000 - 600, 900000, 1000, 880000, &h) == 0 && h == 899999, "10 min old -> tip-1");
    CHECK(el_note_height(1000 - 601, 900000, 1000, 880000, &h) == 0 && h == 899998, "rounds toward older");
    CHECK(el_note_height(0, 900000, 100000000, 880000, &h) == 0 && h == 880000, "ancient -> anchor floor");
    printf("%d passed, %d failed\n", pass, fail);
    return fail != 0;
}
